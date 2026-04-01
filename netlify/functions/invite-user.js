import { createClient } from "@supabase/supabase-js";

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE,
  { auth: { persistSession: false } }
);

const REDIRECT_TO = "https://panel.getcontact.online/auth/callback";
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

  let payload;
  try {
    payload = JSON.parse(event.body || "{}");
  } catch {
    return json(400, { ok: false, error: "bad_json" });
  }

  const ip = getClientIp(event);

  const email = normalize(payload.email, 255).toLowerCase();
  const public_path = normalize(payload.public_path, 100).toLowerCase();
  const name = normalize(payload.name, 100);
  const hp = normalize(payload.hp, 200);
  const turnstileToken = normalize(payload.turnstileToken, 4000);

  if (hp) {
    return json(400, { ok: false, error: "invalid_request" });
  }

  if (!email || !public_path) {
    return json(400, { ok: false, error: "missing_fields" });
  }

  if (!isValidEmail(email)) {
    return json(400, { ok: false, error: "invalid_email" });
  }

  if (!isValidPublicPath(public_path)) {
    return json(400, { ok: false, error: "invalid_public_path" });
  }

  try {
    const ipLimit = await checkRateLimit(`invite:ip:${ip}`, 3, 600);
    if (!ipLimit.allowed) {
      return json(429, {
        ok: false,
        error: "rate_limited",
        retry_after: ipLimit.retry_after_seconds
      });
    }

    const emailLimit = await checkRateLimit(`invite:email:${email}`, 3, 3600);
    if (!emailLimit.allowed) {
      return json(429, {
        ok: false,
        error: "rate_limited",
        retry_after: emailLimit.retry_after_seconds
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
    .select("id, public_path, user_id, customer_id, active")
    .eq("public_path", public_path)
    .maybeSingle();

  if (landingErr) {
    return json(500, { ok: false, error: "request_failed" });
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

  let userId = null;
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
        data: { name }
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
