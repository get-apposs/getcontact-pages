import { createClient } from "@supabase/supabase-js";

//  INSERT do landings wymaga uprawnień admina
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE,
  { auth: { persistSession: false } }
);

const INTERNAL_TOKEN = process.env.INVITE_INTERNAL_TOKEN;

const LIMITS = {
  name: 100,
  public_path: 100,
};

function normalize(value, max) {
  return String(value || "").trim().replace(/\s+/g, " ").slice(0, max);
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

export async function handler(event) {
  if (event.httpMethod !== "POST") {
    return json(405, { ok: false, error: "method_not_allowed" });
  }

  // Weryfikacja tokenu — tylko Make może wywołać
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

  const public_path = normalize(payload.public_path, LIMITS.public_path).toLowerCase();
  const name        = normalize(payload.name,        LIMITS.name);

  if (!public_path || !name) {
    return json(400, { ok: false, error: "missing_fields" });
  }

  if (!isValidPublicPath(public_path)) {
    return json(400, { ok: false, error: "invalid_public_path" });
  }

  // Sprawdź czy landing już istnieje — idempotentny endpoint
  const { data: existing, error: checkErr } = await supabase
    .from("landings")
    .select("id, public_path, active")
    .eq("public_path", public_path)
    .maybeSingle();

  if (checkErr) {
    console.error("landing_check_failed", checkErr.message);
    return json(500, { ok: false, error: "request_failed" });
  }

  if (existing) {
    // Landing już istnieje — zwróć sukces bez duplikatu
    return json(200, { ok: true, skipped: true, reason: "already_exists" });
  }

  // INSERT nowego landingu — bez user_id, zostanie przypisany przez invite-user
  const { error: insertErr } = await supabase
    .from("landings")
    .insert([{
      public_path,
      name,
      active: true,
      user_id: null,
      customer_id: null,
    }]);

  if (insertErr) {
    console.error("landing_insert_failed", insertErr.message);
    return json(500, { ok: false, error: "landing_insert_failed" });
  }

  return json(200, { ok: true, created: true });
}
