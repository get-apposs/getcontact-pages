// netlify/edge-functions/rate-limit.js
// Blokuje IP które przekraczają LIMIT żądań w oknie czasowym WINDOW_MS

const LIMIT = 5;           // max 5 żądań
const WINDOW_MS = 60_000;  // w ciągu 60 sekund

// Prosta mapa w pamięci — działa w ramach jednej instancji Edge
// Do produkcji na większą skalę: zastąp Cloudflare KV lub Upstash Redis
const store = new Map();

export default async function handler(request, context) {
  const ip =
    request.headers.get("x-nf-client-connection-ip") ||
    request.headers.get("x-forwarded-for")?.split(",")[0].trim() ||
    "unknown";

  const now = Date.now();
  const entry = store.get(ip) || { count: 0, resetAt: now + WINDOW_MS };

  // Reset okna jeśli minął czas
  if (now > entry.resetAt) {
    entry.count = 0;
    entry.resetAt = now + WINDOW_MS;
  }

  entry.count += 1;
  store.set(ip, entry);

  if (entry.count > LIMIT) {
    return new Response(
      JSON.stringify({ ok: false, error: "rate_limit_exceeded" }),
      {
        status: 429,
        headers: {
          "Content-Type": "application/json",
          "Retry-After": String(Math.ceil((entry.resetAt - now) / 1000)),
        },
      }
    );
  }

  return context.next();
}

export const config = {
  path: "/api/submit-lead", // ścieżka Twojej funkcji Netlify
};
