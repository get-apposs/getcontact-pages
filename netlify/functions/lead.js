import { createClient } from "@supabase/supabase-js";

// ✅ ZMIANA: anon key zamiast service_role — insert do leads nie wymaga pełnego dostępu
// W Supabase ustaw RLS na tabeli leads: allow insert for anon
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_ANON_KEY,
  { auth: { persistSession: false } }
);

// ✅ Dozwolone originy
const ALLOWED_ORIGINS = ["https://app.getcontact.online"];

// ✅ Limity długości pól
const LIMITS = {
  name: 100,
  email: 254,
  phone: 30,
  public_path: 100,
};

// ✅ Prosta walidacja formatu email
function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

// ✅ Walidacja public_path — tylko litery, cyfry, myślnik, underscore
function isValidPublicPath(path) {
  return /^[a-zA-Z0-9_-]+$/.test(path);
}

function json(status, body, origin) {
  const headers = {
    "Content-Type": "application/json",
    "Cache-Control": "no-store",
  };

  // ✅ CORS — tylko jeśli origin jest na liście
  if (origin && ALLOWED_ORIGINS.includes(origin)) {
    headers["Access-Control-Allow-Origin"] = origin;
    headers["Vary"] = "Origin";
  }

  return {
    statusCode: status,
    headers,
    body: JSON.stringify(body),
  };
}

export async function handler(event) {
  const origin = event.headers?.origin || event.headers?.Origin || "";

  // ✅ Obsługa preflight CORS
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

  // ✅ Trim i wyciągnięcie pól
  const public_path = (payload.public_path || "").trim();
  const name       = (payload.name  || "").trim();
  const email      = (payload.email || "").trim().toLowerCase();
  const phone      = (payload.phone || "").trim();
  const hp         = (payload.hp    || "").trim();

  // ✅ Honeypot
  if (hp) {
    // Zwracamy 200 żeby bot nie wiedział że został zablokowany
    return json(200, { ok: true }, origin);
  }

  // ✅ Wymagane pola
  if (!public_path || !name || !email) {
    return json(400, { ok: false, error: "missing_fields" }, origin);
  }

  // ✅ Walidacja długości
  if (name.length > LIMITS.name) {
    return json(400, { ok: false, error: "field_too_long", field: "name" }, origin);
  }
  if (email.length > LIMITS.email) {
    return json(400, { ok: false, error: "field_too_long", field: "email" }, origin);
  }
  if (phone.length > LIMITS.phone) {
    return json(400, { ok: false, error: "field_too_long", field: "phone" }, origin);
  }
  if (public_path.length > LIMITS.public_path) {
    return json(400, { ok: false, error: "field_too_long", field: "public_path" }, origin);
  }

  // ✅ Walidacja formatu email
  if (!isValidEmail(email)) {
    return json(400, { ok: false, error: "invalid_email" }, origin);
  }

  // ✅ Walidacja formatu public_path
  if (!isValidPublicPath(public_path)) {
    return json(400, { ok: false, error: "invalid_public_path" }, origin);
  }

  // Sprawdzenie czy landing istnieje i jest aktywny
  const { data: landing, error: landingErr } = await supabase
    .from("landings")
    .select("id")
    .eq("public_path", public_path)
    .eq("active", true)
    .single();

  if (landingErr || !landing) {
    // ✅ Nie ujawniamy szczegółów błędu
    return json(404, { ok: false, error: "landing_not_found" }, origin);
  }

  const { error: insertErr } = await supabase
    .from("leads")
    .insert([{ landing_id: landing.id, name, email, phone }]);

  if (insertErr) {
    // ✅ Logujemy szczegóły po stronie serwera, nie wysyłamy do klienta
    console.error("lead_insert_failed", insertErr.message);
    return json(500, { ok: false, error: "lead_insert_failed" }, origin);
  }

  return json(200, { ok: true }, origin);
}
