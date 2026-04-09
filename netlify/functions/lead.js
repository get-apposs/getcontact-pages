import { createClient } from "@supabase/supabase-js";
import { createHash } from "crypto";

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

// Hash IP — nie zapisujemy surowego IP
function hashIp(ip) {
  return createHash("sha256").update(ip + (process.env.IP_SALT || "gc2024")).digest("hex").slice(0, 16);
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function isValidPublicPath(path) {
  return /^[a-zA-Z0-9_-]+$/.test(path);
}

// Sanitizacja — strip HTML przed przetworzeniem
function stripHtml(value) {
  return String(value || "").replace(/<[^>]*>/g, "");
}

function normalizeText(value, max) {
  return stripHtml(value).trim().replace(/\s+/g, " ").slice(0, max);
}

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

return {
  statusCode: 403,
  headers: { "content-type": "application/json" },
  body: JSON.stringify({
    ok: false,
    error: "captcha_failed",
    verifyData
  }),
};


//  Rate limit przez Supabase RPC
async function checkRateLimit(bucket, limit, windowSeconds) {
  const { data, error } = await supabase
    .rpc("check_rate_limit", {
      p_bucket: bucket,
      p_limit: limit,
      p_window_seconds: windowSeconds,
    });

  if (error) {
    console.error("rate_limit_error", error.message);
    return true; // fail open — nie blokuj przy błędzie RPC
  }
  return data === true;
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

  const public_path    = normalizeText(payload.public_path, LIMITS.public_path).toLowerCase();
  const name           = normalizeText(payload.name,        LIMITS.name);
  const email          = normalizeText(payload.email,       LIMITS.email).toLowerCase();
  const phone          = normalizeText(payload.phone,       LIMITS.phone);
  const hp             = String(payload.hp             || "").trim();
  const turnstileToken = String(payload.turnstileToken || "").trim();

  // Honeypot
  if (hp) {
    return json(200, { ok: true }, origin);
  }

  // Turnstile
  if (!turnstileToken) {
    return json(400, { ok: false, error: "missing_captcha" }, origin);
  }

  // Wymagane pola i walidacja formatu — przed rate limitem żeby nie obciążać bazy
  if (!public_path || !name || !email) {
    return json(400, { ok: false, error: "missing_fields" }, origin);
  }

  if (name.length        > LIMITS.name)        return json(400, { ok: false, error: "field_too_long", field: "name" }, origin);
  if (email.length       > LIMITS.email)       return json(400, { ok: false, error: "field_too_long", field: "email" }, origin);
  if (phone.length       > LIMITS.phone)       return json(400, { ok: false, error: "field_too_long", field: "phone" }, origin);
  if (public_path.length > LIMITS.public_path) return json(400, { ok: false, error: "field_too_long", field: "public_path" }, origin);

  if (!isValidEmail(email)) {
    return json(400, { ok: false, error: "invalid_email" }, origin);
  }
  if (!isValidPublicPath(public_path)) {
    return json(400, { ok: false, error: "invalid_public_path" }, origin);
  }

  if (/[<>]/.test(name) || /[<>]/.test(phone)) {
    return json(400, { ok: false, error: "invalid_input" }, origin);
  }

  // Rate limiting — po walidacji, przed Turnstile i bazą
  const ipHash = hashIp(ip);

  // 1. IP + landing — max 5 prób / 10 min
  const ipOk = await checkRateLimit(
    `ip:${ipHash}:${public_path}`,
    5,
    600
  );
  if (!ipOk) {
    return json(429, { ok: false, error: "rate_limited" }, origin);
  }

  // 2. Email + landing — max 3 próby / 24h
  const emailHash = createHash("sha256").update(email).digest("hex").slice(0, 16);
  const emailOk = await checkRateLimit(
    `email:${emailHash}:${public_path}`,
    3,
    86400
  );
  if (!emailOk) {
    return json(429, { ok: false, error: "rate_limited" }, origin);
  }

  // 3. Landing — max 100 leadów / godzinę
  const landingOk = await checkRateLimit(
    `landing:${public_path}`,
    100,
    3600
  );
  if (!landingOk) {
    return json(429, { ok: false, error: "rate_limited" }, origin);
  }

  // Turnstile — po rate limicie żeby nie płacić za weryfikację zablokowanych
  const turnstileOk = await verifyTurnstile(turnstileToken, ip);
  if (!turnstileOk) {
    return json(403, { ok: false, error: "captcha_failed" }, origin);
  }

  // Sprawdzenie landingu przez RPC
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
