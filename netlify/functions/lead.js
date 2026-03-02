import { createClient } from "@supabase/supabase-js";

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE; // rozważ zmienić nazwę ENV na ..._KEY
const ADMIN_NOTIFY_WEBHOOK = process.env.ADMIN_NOTIFY_WEBHOOK;

const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
  auth: { persistSession: false },
});

function json(status, body) {
  return {
    statusCode: status,
    headers: { "Content-Type": "application/json", "Cache-Control": "no-store" },
    body: JSON.stringify(body),
  };
}

export async function handler(event) {
  if (event.httpMethod !== "POST") return json(405, { ok: false });

  let payload;
  try {
    payload = JSON.parse(event.body || "{}");
  } catch {
    return json(400, { ok: false, error: "bad_json" });
  }

  const email = (payload.email || "").trim().toLowerCase();
  const landing_path = (payload.landing_path || "").trim();
  const brand_name = (payload.brand_name || "").trim();

  if (!email || !landing_path) return json(400, { ok: false, error: "missing_fields" });

  
  const redirectTo = payload.redirectTo || "https://panel.getcontact.online/auth/callback";

  // 1) Zaproś usera (Supabase wyśle maila z linkiem)
  const { data: invited, error: inviteErr } =
    await supabase.auth.admin.inviteUserByEmail(email, { redirectTo });

  if (inviteErr) {
    // jeśli user już istnieje, invite może zwrócić błąd zależnie od sytuacji
    return json(500, { ok: false, error: "invite_failed", details: inviteErr.message });
  }

  const user_id = invited?.user?.id;
  if (!user_id) return json(500, { ok: false, error: "missing_user_id" });

  // 2) Upsert landingu (nadpisze/uzupełni user_id, brand_name, active)
  const { error: landingErr } = await supabase
    .from("landings")
    .upsert(
      [{ public_path: landing_path, user_id, brand_name, active: true }],
      { onConflict: "public_path" }
    );

  if (landingErr) {
    return json(500, { ok: false, error: "landing_upsert_failed", details: landingErr.message });
  }

  // 3) Powiadomienie do Ciebie
  if (ADMIN_NOTIFY_WEBHOOK) {
    await fetch(ADMIN_NOTIFY_WEBHOOK, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        text: `🆕 Nowy klient\nEmail: ${email}\nLanding: ${landing_path}\nBrand: ${brand_name}`,
      }),
    }).catch(() => {});
  }

  return json(200, { ok: true, user_id });
}
