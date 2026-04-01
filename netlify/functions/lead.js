import { createClient } from "@supabase/supabase-js";

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE,
  { auth: { persistSession: false } }
);

const REDIRECT_TO = "https://panel.getcontact.online/auth/callback";

function json(status: number, body: Record<string, unknown>) {
  return {
    statusCode: status,
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": "no-store"
    },
    body: JSON.stringify(body)
  };
}

function isValidEmail(email: string) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) && email.length <= 255;
}

function isValidPublicPath(value: string) {
  return /^[a-z0-9-]{1,100}$/.test(value);
}

function sanitizeName(value: unknown) {
  return String(value || "")
    .trim()
    .replace(/\s+/g, " ")
    .slice(0, 100);
}

async function findUserIdByEmail(email: string): Promise<string | null> {
  const { data, error } = await supabase
    .from("profiles")
    .select("id")
    .eq("email", email)
    .maybeSingle();

  if (error) {
    throw new Error("profile_lookup_failed");
  }

  return data?.id || null;
}

export async function handler(event: any) {
  if (event.httpMethod !== "POST") {
    return json(405, { ok: false, error: "method_not_allowed" });
  }

  let payload: any;
  try {
    payload = JSON.parse(event.body || "{}");
  } catch {
    return json(400, { ok: false, error: "bad_json" });
  }

  const email = String(payload.email || "").trim().toLowerCase();
  const public_path = String(payload.public_path || "").trim().toLowerCase();
  const name = sanitizeName(payload.name);

  if (!email || !public_path) {
    return json(400, { ok: false, error: "missing_fields" });
  }

  if (!isValidEmail(email)) {
    return json(400, { ok: false, error: "invalid_email" });
  }

  if (!isValidPublicPath(public_path)) {
    return json(400, { ok: false, error: "invalid_public_path" });
  }

  const { data: landing, error: landingErr } = await supabase
    .from("landings")
    .select("id, user_id, public_path")
    .eq("public_path", public_path)
    .maybeSingle();

  if (landingErr) {
    return json(500, { ok: false, error: "landing_check_failed" });
  }

  if (!landing) {
    return json(404, { ok: false, error: "landing_not_found" });
  }

  if (landing.user_id) {
    return json(200, {
      ok: true,
      skipped: true,
      reason: "landing_already_connected"
    });
  }

  let userId: string | null = null;
  let invitedNewUser = false;

  try {
    userId = await findUserIdByEmail(email);
  } catch {
    return json(500, { ok: false, error: "user_lookup_failed" });
  }

  if (!userId) {
    const { data: invited, error: inviteErr } =
      await supabase.auth.admin.inviteUserByEmail(email, {
        redirectTo: REDIRECT_TO,
        data: {
          name
        }
      });

    if (inviteErr) {
      return json(500, { ok: false, error: "invite_failed" });
    }

    userId = invited?.user?.id || null;
    invitedNewUser = true;
  }

  if (!userId) {
    return json(500, { ok: false, error: "missing_user_id" });
  }

  const { error: updateErr } = await supabase
    .from("landings")
    .update({
      user_id: userId,
      customer_id: userId,
      name: name || landing.public_path,
      active: true
    })
    .eq("id", landing.id)
    .is("user_id", null);

  if (updateErr) {
    return json(500, { ok: false, error: "landing_update_failed" });
  }

  const { data: freshLanding, error: freshErr } = await supabase
    .from("landings")
    .select("id, public_path, user_id, customer_id, active")
    .eq("id", landing.id)
    .maybeSingle();

  if (freshErr) {
    return json(500, { ok: false, error: "landing_reload_failed" });
  }

  if (!freshLanding?.user_id) {
    return json(409, { ok: false, error: "landing_connect_conflict" });
  }

  return json(200, {
    ok: true,
    invited_new_user: invitedNewUser,
    user_id: freshLanding.user_id,
    landing: freshLanding
  });
}
