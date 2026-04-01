import { createClient } from "@supabase/supabase-js";

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE,
  { auth: { persistSession: false } }
);

const TURNSTILE_SECRET = process.env.TURNSTILE_SECRET;

function json(status, body) {
  return {
    statusCode: status,
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": "no-store"
    },
    body: JSON.stringify(body)
  };
}

function getClientIp(event) {
  const h = event.headers || {};
  return (
    h["x-nf-client-connection-ip"] ||
    h["client-ip"] ||
    (h["x-forwarded-for"] || "").split(",")[0].trim() ||
    "unknown"
  );
}

function normalize(value, max = 255) {
  return String(value || "").trim().replace(/\s+/g, " ").slice(0, max);
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) && email.length <= 255;
}

function isValidPhone(phone) {
  if (!phone) return true;
  return /^[0-9+\-\s()]{6,30}$/.test(phone);
}

function isValidPublicPath(value) {
  return /^[a-z0-9-]{1,100}$/.test(value);
}

async function verifyTurnstile(token, ip) {
  if (!TURNSTILE_SECRET) return false;
  if (!token) return false;

  const resp = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      secret: TURNSTILE_SECRET,
      response: token,
      remoteip: ip
    })
  });

  if (!resp.ok) return false;

  const data = await resp.json();
  return data.success === true;
}

async function checkRateLimit(bucket, limit, windowSeconds) {
  const { data, error } = await supabase.rpc("check_rate_limit", {
    p_bucket: bucket,
    p_limit: limit,
    p_window_seconds: windowSeconds
  });

  if (error) throw error;
  return data?.[0] || { allowed: false, retry_after_seconds: windowSeconds };
}

export async function handler(event) {
  if (event.httpMethod !== "POST") {
    return json(405, { ok: false, error: "method_not_allowed" });
  }

  let payload;
  try {
    payload = JSON.parse(event.body || "{}");
  } catch {
    return json(400, { ok: false, error: "bad_json" });
  }

  const ip = getClientIp(event);

  const public_path = normalize(payload.public_path, 100).toLowerCase();
  const name = normalize(payload.name, 100);
  const email = normalize(payload.email, 255).toLowerCase();
  const phone = normalize(payload.phone, 30);
  const service = normalize(payload.service, 120);
  const hp = normalize(payload.hp, 200);
  const turnstileToken = normalize(payload.turnstileToken, 4000);

  if (hp) {
    return json(400, { ok: false, error: "invalid_request" });
  }

  if (!public_path || !name || !email) {
    return json(400, { ok: false, error: "missing_fields" });
  }

  if (!isValidPublicPath(public_path)) {
    return json(400, { ok: false, error: "invalid_public_path" });
  }

  if (!isValidEmail(email)) {
    return json(400, { ok: false, error: "invalid_email" });
  }

  if (!isValidPhone(phone)) {
    return json(400, { ok: false, error: "invalid_phone" });
  }

  try {
    const ipLimit = await checkRateLimit(`lead:ip:${ip}`, 5, 300);
    if (!ipLimit.allowed) {
      return json(429, {
        ok: false,
        error: "rate_limited",
        retry_after: ipLimit.retry_after_seconds
      });
    }

    const landingLimit = await checkRateLimit(`lead:path:${public_path}`, 20, 300);
    if (!landingLimit.allowed) {
      return json(429, {
        ok: false,
        error: "rate_limited",
        retry_after: landingLimit.retry_after_seconds
      });
    }
  } catch {
    return json(500, { ok: false, error: "rate_limit_failed" });
  }

  const turnstileOk = await verifyTurnstile(turnstileToken, ip);
  if (!turnstileOk) {
    return json(400, { ok: false, error: "captcha_failed" });
  }

  const { data: landing, error: landingErr } = await supabase
    .from("landings")
    .select("id")
    .eq("public_path", public_path)
    .eq("active", true)
    .maybeSingle();

  if (landingErr) {
    return json(500, { ok: false, error: "request_failed" });
  }

  if (!landing) {
    return json(404, { ok: false, error: "landing_not_found" });
  }

  const { error: insertErr } = await supabase
    .from("leads")
    .insert([
      {
        landing_id: landing.id,
        name,
        email,
        phone: phone || null,
        service: service || null
      }
    ]);

  if (insertErr) {
    return json(500, { ok: false, error: "request_failed" });
  }

  return json(200, { ok: true });
}
