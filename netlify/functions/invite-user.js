import { createClient } from "@supabase/supabase-js";

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE,
  { auth: { persistSession: false } }
);

const REDIRECT_TO = "https://panel.getcontact.online/auth/callback";
const INTERNAL_TOKEN = process.env.INVITE_INTERNAL_TOKEN;

const LIMITS = {
  name: 100,
  email: 254,
  public_path: 100,
};

function normalize(value, max) {
  return String(value || "").trim().replace(/\s+/g, " ").slice(0, max);
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function isValidPublicPath(value) {
  return /^[a-z0-9-]{1,100}$/.test(value);
}

function json(status, body) {
  return {
    statusCode: status,
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": "no-store",
    },
    body: JSON.stringify(body),
  };
}

async function findUserIdByEmail(email) {
  const { data, error } = await supabase
    .from("profiles")
    .select("id")
    .eq("email", email)
    .maybeSingle();

  if (error) throw error;
  return data?.id || null;
}

export async function handler(event) {
  if (event.httpMethod !== "POST") {
    return json(405, { ok: false, error: "method_not_allowed" });
  }

  const incomingToken =
    event.headers?.["x-internal-token"] ||
    event.headers?.["X-Internal-Token"] ||
    "";

  if (!INTERNAL_TOKEN || incomingToken !== INTERNAL_TOKEN) {
    return json(401, { ok: false, error: "unauthorized" });
  }

  let payload;
  try {
    payload = JSON.parse(event.body || "{}");
  } catch {
    return json(400, { ok: false, error: "bad_json" });
  }

  const email       = normalize(payload.email,       LIMITS.email).toLowerCase();
  const public_path = normalize(payload.public_path, LIMITS.public_path).toLowerCase();
  const name        = normalize(payload.name,        LIMITS.name);

  if (!email || !public_path || !name) {
    return json(400, { ok: false, error: "missing_fields" });
  }

  if (!isValidEmail(email)) {
    return json(400, { ok: false, error: "invalid_email" });
  }

  if (!isValidPublicPath(public_path)) {
    return json(400, { ok: false, error: "invalid_public_path" });
  }

  // ✅ Zawężone do active = true — nie przypinamy do wyłączonych landingów
  const { data: landing, error: landingErr } = await supabase
    .from("landings")
    .select("id, user_id")
    .eq("public_path", public_path)
    .eq("active", true)
    .maybeSingle();

  if (landingErr) {
    return json(500, { ok: false, error: "request_failed" });
  }

  if (!landing) {
    return json(404, { ok: false, error: "landing_not_found" });
  }

  if (landing.user_id) {
    return json(200, { ok: true, skipped: true, reason: "already_connected" });
  }

  let userId = null;
  let invitedNewUser = false;

  const { data: invited, error: inviteErr } =
    await supabase.auth.admin.inviteUserByEmail(email, {
      redirectTo: REDIRECT_TO,
      data: { name },
    });

  if (!inviteErr) {
    // ✅ Nowy user — id mamy bezpośrednio z invite, nie potrzebujemy profiles
    userId = invited?.user?.id || null;
    invitedNewUser = true;
  } else {
    // ✅ Bardziej odporny warunek — toLowerCase zamiast exact match
    const msg = inviteErr.message || "";

    if (msg.toLowerCase().includes("already")) {
      // User istnieje — szukamy w profiles
      try {
        userId = await findUserIdByEmail(email);
      } catch {
        return json(500, { ok: false, error: "user_lookup_failed" });
      }

      // ✅ Fallback timing — trigger mógł jeszcze nie zdążyć wpisać do profiles
      if (!userId) {
        await new Promise((r) => setTimeout(r, 200));
        try {
          userId = await findUserIdByEmail(email);
        } catch {
          return json(500, { ok: false, error: "user_lookup_failed" });
        }
      }

      // Stary user sprzed triggera — nie ma go w profiles
      if (!userId) {
        console.error("user_not_in_profiles", email);
        return json(500, { ok: false, error: "user_not_found_in_profiles" });
      }
    } else {
      console.error("invite_failed", msg);
      return json(500, { ok: false, error: "invite_failed" });
    }
  }

  if (!userId) {
    return json(500, { ok: false, error: "missing_user_id" });
  }

  // ✅ Race condition guard — update tylko jeśli user_id nadal null
  const { error: updateErr } = await supabase
    .from("landings")
    .update({
      user_id: userId,
      customer_id: userId,
      active: true,
    })
    .eq("id", landing.id)
    .is("user_id", null);

  if (updateErr) {
    console.error("landing_update_failed", updateErr.message);
    return json(500, { ok: false, error: "landing_update_failed" });
  }

  // Weryfikacja końcowa
  const { data: fresh, error: freshErr } = await supabase
    .from("landings")
    .select("user_id")
    .eq("id", landing.id)
    .maybeSingle();

  if (freshErr) {
    return json(500, { ok: false, error: "landing_reload_failed" });
  }

  if (!fresh?.user_id) {
    return json(409, { ok: false, error: "landing_connect_conflict" });
  }

  return json(200, {
    ok: true,
    invited_new_user: invitedNewUser,
  });
}
