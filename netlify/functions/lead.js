import { createClient } from "@supabase/supabase-js";

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_ANON_KEY,
  { auth: { persistSession: false } }
);

const ALLOWED_ORIGINS = ["https://app.getcontact.online"];

const LIMITS = {
  name: 100,
  email: 254,
  phone: 30,
  public_path: 100,
};

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function isValidPublicPath(path) {
  return /^[a-zA-Z0-9_-]+$/.test(path);
}

// ✅ Weryfikacja tokenu Turnstile po stronie serwera
async function verifyTurnstile(token, ip) {
  const resp = await fetch(
    "https://challenges.cloudflare.com/turnstile/v0/siteverify",
    {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        secret: process.env.TURNSTILE_SECRET_KEY,
        response: token,
        remoteip: ip || "",
      }),
    }
  );
  const result = await resp.json();
  return result.success === true;
}

function json(status, body, origin) {
  const headers = {
    "Content-Type": "application/json",
    "Cache-Control": "no-store",
  };
  if (origin && ALLOWED_ORIGINS.includes(origin)) {
    headers["Access-Control-Allow-Origin"] = origin;
    headers["Vary"] = "Origin";
  }
  return { statusCode: status, headers, body: JSON.stringify(body) };
}

export async function handler(event) {
  const origin = event.headers?.origin || event.headers?.Origin || "";
  const ip =
    event.headers?.["x-nf-client-connection-ip"] ||
    event.headers?.["x-forwarded-for"]?.split(",")[0].trim() ||
    "";

  // Preflight CORS
  if (event.httpMethod === "OPTIONS") {
    if (ALLOWED_ORIGINS.includes(origin)) {
      return {
        statusCode: 204,
        headers: {
          "Access-Control-Allow-Origin": origin,
          "Access-Control-Allow-Methods": "POST, OPTIONS",
          "Access-Control-Allow-Headers": "Content-Type",
          "Vary": "Origin",
        },
        body: "",
      };
    }
    return { statusCode: 403, body: "" };
  }

  if (event.httpMethod !== "POST") {
    return json(405, { ok: false, error: "method_not_allowed" }, origin);
  }

  let payload;
  try {
    payload = JSON.parse(event.body || "{}");
  } catch {
    return json(400, { ok: false, error: "bad_json" }, origin);
  }

  const public_path    = (payload.public_path    || "").trim();
  const name           = (payload.name           || "").trim();
  const email          = (payload.email          || "").trim().toLowerCase();
  const phone          = (payload.phone          || "").trim();
  const hp             = (payload.hp             || "").trim();
  const turnstileToken = (payload.turnstileToken || "").trim();

  // Honeypot
  if (hp) {
    return json(200, { ok: true }, origin); // bot nie wie że jest blokowany
  }

  // ✅ Weryfikacja Turnstile — przed wszystkim innym
  if (!turnstileToken) {
    return json(400, { ok: false, error: "missing_captcha" }, origin);
  }
  const turnstileOk = await verifyTurnstile(turnstileToken, ip);
  if (!turnstileOk) {
    return json(403, { ok: false, error: "captcha_failed" }, origin);
  }

  // Wymagane pola
  if (!public_path || !name || !email) {
    return json(400, { ok: false, error: "missing_fields" }, origin);
  }

  // Walidacja długości
  if (name.length        > LIMITS.name)        return json(400, { ok: false, error: "field_too_long", field: "name" }, origin);
  if (email.length       > LIMITS.email)       return json(400, { ok: false, error: "field_too_long", field: "email" }, origin);
  if (phone.length       > LIMITS.phone)       return json(400, { ok: false, error: "field_too_long", field: "phone" }, origin);
  if (public_path.length > LIMITS.public_path) return json(400, { ok: false, error: "field_too_long", field: "public_path" }, origin);

  // Walidacja formatu
  if (!isValidEmail(email)) {
    return json(400, { ok: false, error: "invalid_email" }, origin);
  }
  if (!isValidPublicPath(public_path)) {
    return json(400, { ok: false, error: "invalid_public_path" }, origin);
  }

  // Sprawdzenie landingu
const { data: landingId, error: landingErr } = await supabase
  .rpc("get_landing_id", { p_public_path: public_path });

if (landingErr || !landingId) {
  return json(404, { ok: false, error: "landing_not_found" }, origin);
}

  // Insert leada
  const { error: insertErr } = await supabase
    .from("leads")
    .insert([{ landing_id: landingId, name, email, phone }]);

  if (insertErr) {
    console.error("lead_insert_failed", insertErr.message);
    return json(500, { ok: false, error: "lead_insert_failed" }, origin);
  }

  return json(200, { ok: true }, origin);
}
