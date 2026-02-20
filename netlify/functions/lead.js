// netlify/functions/lead.js
import crypto from "crypto";
import { createClient } from "@supabase/supabase-js";

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_ROLE = process.env.SUPABASE_SERVICE_ROLE;

const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE, {
  auth: { persistSession: false },
});

function json(statusCode, obj) {
  return {
    statusCode,
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": "no-store",
    },
    body: JSON.stringify(obj),
  };
}

function normStr(v, max = 200) {
  if (typeof v !== "string") return "";
  return v.trim().slice(0, max);
}

function isEmail(v) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v);
}

function isPhone(v) {
  // luźna walidacja PL/EU, bez przesady
  return /^[0-9+\s()-]{7,20}$/.test(v);
}

function sha256(s) {
  return crypto.createHash("sha256").update(s).digest("hex");
}

export async function handler(event) {
  if (event.httpMethod !== "POST") return json(405, { ok: false });

  let payload;
  try {
    payload = JSON.parse(event.body || "{}");
  } catch {
    return json(400, { ok: false, error: "bad_json" });
  }

  // honeypot (ukryte pole w formularzu)
  const hp = normStr(payload.hp, 200);
  if (hp) return json(200, { ok: true }); // cicho, żeby bot nie wiedział

  const public_path = normStr(payload.public_path, 120);
  const email = normStr(payload.email, 120);
  const phone = normStr(payload.phone, 40);
  const name = normStr(payload.name, 80);
  const service = normStr(payload.service, 80);

  const utm_source = normStr(payload.utm_source, 120);
  const utm_campaign = normStr(payload.utm_campaign, 120);

  if (!public_path) return json(400, { ok: false, error: "missing_public_path" });

  // minimum: wymagamy email lub telefon (albo oba)
  if (!email && !phone) return json(400, { ok: false, error: "missing_contact" });
  if (email && !isEmail(email)) return json(400, { ok: false, error: "bad_email" });
  if (phone && !isPhone(phone)) return json(400, { ok: false, error: "bad_phone" });

  // IP hash (nie zapisujemy surowego IP)
  const ip =
    (event.headers["x-nf-client-connection-ip"] ||
      event.headers["x-forwarded-for"] ||
      "")
      .split(",")[0]
      .trim();

  const ipHash = ip ? sha256(ip) : "noip";

  // --- RATE LIMIT (prosty) ---
  // okno 10 minut, limit 10 requestów / IP / landing
  const now = new Date();
  const windowMinutes = 10;
  const limit = 10;

  const windowKey = `${now.getUTCFullYear()}${String(now.getUTCMonth() + 1).padStart(2, "0")}${String(
    now.getUTCDate()
  ).padStart(2, "0")}${String(now.getUTCHours()).padStart(2, "0")}${String(
    Math.floor(now.getUTCMinutes() / windowMinutes) * windowMinutes
  ).padStart(2, "0")}`;

  const rlKey = `${ipHash}:${public_path}:${windowKey}`;
  const windowEndsAt = new Date(
    Date.UTC(
      now.getUTCFullYear(),
      now.getUTCMonth(),
      now.getUTCDate(),
      now.getUTCHours(),
      Math.floor(now.getUTCMinutes() / windowMinutes) * windowMinutes + windowMinutes,
      0
    )
  ).toISOString();

  // Upsert licznik
  const { data: rlRow, error: rlErr } = await supabase
    .from("rate_limits")
    .select("count, window_ends_at")
    .eq("key", rlKey)
    .maybeSingle();

  if (rlErr) return json(500, { ok: false, error: "rl_read_failed" });

  if (!rlRow) {
    const { error: insErr } = await supabase
      .from("rate_limits")
      .insert([{ key: rlKey, count: 1, window_ends_at: windowEndsAt }]);
    if (insErr) return json(500, { ok: false, error: "rl_insert_failed" });
  } else {
    if (rlRow.count >= limit) return json(429, { ok: false, error: "rate_limited" });
    const { error: updErr } = await supabase
      .from("rate_limits")
      .update({ count: rlRow.count + 1 })
      .eq("key", rlKey);
    if (updErr) return json(500, { ok: false, error: "rl_update_failed" });
  }

  // --- lookup landing po public_path ---
  const { data: landing, error: landingErr } = await supabase
    .from("landings")
    .select("id, active")
    .eq("public_path", public_path)
    .maybeSingle();

  if (landingErr) return json(500, { ok: false, error: "landing_lookup_failed" });
  if (!landing) return json(404, { ok: false, error: "landing_not_found" });
  if (landing.active === false) return json(403, { ok: false, error: "landing_inactive" });

  // --- zapis lead ---
  const { error: leadErr } = await supabase.from("leads").insert([
    {
      landing_id: landing.id,
      phone,
      email,
      name,
      service,
      utm_source,
      utm_campaign,
    },
  ]);

  if (leadErr) return json(500, { ok: false, error: "lead_insert_failed" });

  return json(200, { ok: true });
}
