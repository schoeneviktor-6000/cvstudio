/**
 * CVStudio Worker (cvstudio.work) — API
 *
 * Goals:
 * - Let users try CV tailoring immediately (no login) on the landing page
 * - Give X free tailorings (default 3) per browser/device, then return a paywall response
 * - Keep it fast + cost-safe (KV caching + basic cooldown)
 *
 * Required bindings:
 * - KV: ANON_KV
 *
 * Required secrets/vars (set in Cloudflare Worker settings or via wrangler):
 * - GEMINI_API_KEY (secret)  -> Google AI Studio key (Generative Language API)
 *   OR (Vertex fallback)
 * - GCP_SA_KEY_JSON (secret) -> service account JSON (for OAuth)
 * - GEMINI_VERTEX_PROJECT_ID (text) optional (or comes from SA json)
 * - GEMINI_VERTEX_LOCATION (text) optional (default us-central1)
 *
 * Optional vars:
 * - FREE_TAILOR_LIMIT (text) default "3"       (set to "1" later if you want)
 * - ANON_USAGE_TTL_DAYS (text) default "90"    (how long anon usage records stay)
 * - ANON_COOLDOWN_MS (text) default "15000"    (anti-spam cooldown)
 * - CACHE_SECONDS (text) default "3600"        (cache identical requests)
 * - GEMINI_TAILOR_MODELS (text) default "gemini-2.0-pro,gemini-2.0-flash"
 * - GEMINI_API_BASE (text) "aistudio"|"vertex"|"auto" (default auto)
 * - CORS_ORIGINS (text) comma-separated allowlist; if empty -> permissive
 */

const SERVICE_NAME = "cvstudio-api";
const VERSION = "v1.0.0";

// -----------------------------
// Router
// -----------------------------
export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // CORS preflight
    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders(request, env) });
    }

    try {
      if (url.pathname === "/" && request.method === "GET") {
        return json(request, env, {
          ok: true,
          service: SERVICE_NAME,
          version: VERSION,
          routes: ["GET /health", "GET /api/usage", "POST /api/tailor"],
        });
      }

      if (url.pathname === "/health" && request.method === "GET") {
        return json(request, env, { ok: true, service: SERVICE_NAME, time: new Date().toISOString() });
      }

      if (url.pathname === "/api/usage" && request.method === "GET") {
        return await handleUsage(request, env);
      }

      if (url.pathname === "/api/tailor" && request.method === "POST") {
        return await handleTailor(request, env);
      }

      return json(request, env, { ok: false, error: "Not found" }, 404);
    } catch (err) {
      const details = String(err?.stack || err?.message || err || "");
      return json(request, env, { ok: false, error: "Unhandled error", details: details.slice(0, 1600) }, 500);
    }
  },
};

// -----------------------------
// Core handlers
// -----------------------------
async function handleUsage(request, env) {
  const kv = mustKv(env);
  const anon = getOrCreateAnonId(request);
  const usage = await readAnonUsage(kv, anon.anonId, env);

  const limit = getFreeLimit(env);
  const remaining = limit <= 0 ? null : Math.max(0, limit - usage.tailor_count);

  return json(
    request,
    env,
    {
      ok: true,
      anon_id: anon.anonId,
      free_limit: limit <= 0 ? "unlimited" : limit,
      used: usage.tailor_count,
      remaining,
    },
    200,
    anon.setCookie ? { "Set-Cookie": anon.setCookie } : {}
  );
}

async function handleTailor(request, env) {
  const kv = mustKv(env);
  const anon = getOrCreateAnonId(request);

  // Parse JSON
  let body = null;
  try {
    body = await request.json();
  } catch {
    return json(request, env, { ok: false, error: "Invalid JSON body" }, 400, anon.setCookie ? { "Set-Cookie": anon.setCookie } : {});
  }

  const cvTextRaw = String(body?.cv_text || body?.cv || "").trim();
  const jdRaw = String(body?.job_description || body?.jd || body?.description || "").trim();

  if (!cvTextRaw || cvTextRaw.length < 120) {
    return json(
      request,
      env,
      { ok: false, error: "cv_text is required (min 120 characters)." },
      400,
      anon.setCookie ? { "Set-Cookie": anon.setCookie } : {}
    );
  }

  if (!jdRaw || jdRaw.length < 80) {
    return json(
      request,
      env,
      { ok: false, error: "job_description is required (min 80 characters)." },
      400,
      anon.setCookie ? { "Set-Cookie": anon.setCookie } : {}
    );
  }

  // Safety limits (cost + performance)
  const CV_MAX = 22000;
  const JD_MAX = 60000;

  const cvText = cvTextRaw.slice(0, CV_MAX);
  const jobDescription = jdRaw.slice(0, JD_MAX);

  const strength = normalizeStrength(body?.strength);
  const languageHint = normalizeLanguageHint(body?.language_hint || body?.lang || "auto");

  const jobTitle = String(body?.job_title || body?.title || "").trim().slice(0, 140);
  const companyName = String(body?.company_name || body?.company || "").trim().slice(0, 140);

  // Input hash for caching (prevents burning free credits on refresh)
  const promptVersion = "cvstudio_tailor_prompt_v1";
  const inputHash = await sha256Hex([promptVersion, strength, languageHint, cvText, jobDescription].join("|"));
  const cacheKey = `cache:tailor:${inputHash}`;

  // Return cached result if present (even if user is past the free limit)
  const cached = await kv.get(cacheKey, "json").catch(() => null);
  if (cached?.result?.cv_text) {
    const usageNow = await readAnonUsage(kv, anon.anonId, env);
    const limit = getFreeLimit(env);
    const remaining = limit <= 0 ? null : Math.max(0, limit - usageNow.tailor_count);

    return json(
      request,
      env,
      {
        ok: true,
        cached: true,
        anon_id: anon.anonId,
        remaining_free: remaining,
        result: cached.result,
      },
      200,
      anon.setCookie ? { "Set-Cookie": anon.setCookie } : {}
    );
  }

  // Basic cooldown to reduce spam
  const cooldownMs = clampInt(env.ANON_COOLDOWN_MS, 0, 120000, 15000);
  if (cooldownMs > 0) {
    const cdKey = `anon:${anon.anonId}:cooldown`;
    const last = Number(await kv.get(cdKey).catch(() => "0")) || 0;
    const now = Date.now();
    const delta = now - last;
    if (last && delta < cooldownMs) {
      return json(
        request,
        env,
        {
          ok: false,
          code: "RATE_LIMIT",
          error: "Please wait a moment and try again.",
          retry_after_ms: cooldownMs - delta,
        },
        429,
        anon.setCookie ? { "Set-Cookie": anon.setCookie } : {}
      );
    }
    await kv.put(cdKey, String(now), { expirationTtl: Math.ceil(cooldownMs / 1000) + 10 }).catch(() => {});
  }

  // Enforce free limit (default: 3)
  const limit = getFreeLimit(env);
  const usage = await readAnonUsage(kv, anon.anonId, env);

  if (limit > 0 && usage.tailor_count >= limit) {
    return json(
      request,
      env,
      {
        ok: false,
        code: "PAYWALL",
        error: "Free CV tailoring limit reached.",
        message:
          "Create an account to continue tailoring and to save your CV versions. (You’ll keep the quality, just unlock more runs.)",
        free_limit: limit,
        used: usage.tailor_count,
        remaining_free: 0,
      },
      402,
      anon.setCookie ? { "Set-Cookie": anon.setCookie } : {}
    );
  }

  // Build prompt for Gemini
  const promptText = buildTailorPrompt({
    cvText,
    jobDescription,
    strength,
    languageHint,
    jobTitle,
    companyName,
  });

  const models =
    String(env.GEMINI_TAILOR_MODELS || "").trim() || "gemini-2.0-pro,gemini-2.0-flash";

  // Generate
  const maxOut = clampInt(env.GEMINI_TAILOR_MAX_OUTPUT_TOKENS, 800, 12000, 5200);

  const gen = await geminiGenerateJsonWithModels(env, {
    models,
    promptText,
    temperature: 0.2,
    maxOutputTokens: maxOut,
  });

  const parsed = normalizeTailorOutput(gen.parsed);

  // Derive keyword insights (more reliable than “model guessing”)
  const keywords = dedupeStrings(parsed.ats_keywords).slice(0, 40);

  const originalLower = cvText.toLowerCase();
  const outCvText = String(parsed.cv_text || "").trim();
  const outLower = outCvText.toLowerCase();

  const alreadyPresent = [];
  const added = [];
  const stillMissing = [];

  for (const kw of keywords) {
    const inOriginal = keywordInText(originalLower, kw);
    const inOut = keywordInText(outLower, kw);

    if (inOriginal) alreadyPresent.push(kw);
    else if (inOut) added.push(kw);
    else stillMissing.push(kw);

    if (alreadyPresent.length + added.length + stillMissing.length >= 120) break;
  }

  const result = {
    language: parsed.language || (languageHint === "auto" ? null : languageHint),
    cv_text: outCvText,
    ats_keywords: keywords,
    ats_keywords_already_present: alreadyPresent,
    ats_keywords_added: added,
    ats_keywords_still_missing: stillMissing,
    changes: dedupeStrings(parsed.changes).slice(0, 12),
    warnings: dedupeStrings(parsed.warnings).slice(0, 12),
    confidence: typeof parsed.confidence === "number" ? clamp(parsed.confidence, 0, 1) : null,
    model: gen.model,
    prompt_version: promptVersion,
  };

  // Cache the result (so refresh doesn’t burn free runs)
  const cacheSeconds = clampInt(env.CACHE_SECONDS, 60, 86400, 3600);
  await kv
    .put(cacheKey, JSON.stringify({ result, created_at: new Date().toISOString() }), { expirationTtl: cacheSeconds })
    .catch(() => {});

  // Increment usage only on successful generation
  await incrementAnonUsage(kv, anon.anonId, env);

  const usageAfter = await readAnonUsage(kv, anon.anonId, env);
  const remaining = limit <= 0 ? null : Math.max(0, limit - usageAfter.tailor_count);

  return json(
    request,
    env,
    {
      ok: true,
      cached: false,
      anon_id: anon.anonId,
      free_limit: limit <= 0 ? "unlimited" : limit,
      used: usageAfter.tailor_count,
      remaining_free: remaining,
      result,
    },
    200,
    anon.setCookie ? { "Set-Cookie": anon.setCookie } : {}
  );
}

// -----------------------------
// Prompt
// -----------------------------
function buildTailorPrompt({ cvText, jobDescription, strength, languageHint, jobTitle, companyName }) {
  const strengthLabel =
    strength === "light" ? "LIGHT" : strength === "strong" ? "STRONG" : "BALANCED";

  const langLine =
    languageHint && languageHint !== "auto"
      ? `Write in ${languageHint.toUpperCase()} only.`
      : "Write in the same language as the job description.";

  const roleLine = jobTitle ? `Target role: ${jobTitle}` : "Target role: (infer from job description)";
  const companyLine = companyName ? `Company: ${companyName}` : "Company: (not provided)";

  return `
You are CVStudio: an expert corporate CV writer and ATS optimization specialist.
Your job: tailor the candidate's CV to the job description to maximize ATS match and recruiter readability.
You MUST stay truthful: do NOT invent skills, degrees, employers, titles, years, tools, certifications, or achievements.
If a keyword is not supported by the CV, do NOT add it as a claimed skill; you may suggest it as "consider adding if true" in warnings.

STYLE:
- Output must be clean, professional, ATS-friendly plain text
- Use consistent section headers
- Strong action verbs, quantified impact when already present
- Keep it concise (aim: 1–2 pages of text)
- Do not include images, tables, columns, or fancy formatting

TAILORING STRENGTH: ${strengthLabel}
${langLine}
${roleLine}
${companyLine}

OUTPUT FORMAT:
Return ONLY valid JSON (no markdown, no code fences). Schema:

{
  "language": "en" | "de",
  "ats_keywords": [string, ...],          // 20-35 keywords/phrases directly from the job description (ATS terms)
  "cv_text": string,                      // final tailored CV as plain text
  "changes": [string, ...],               // 6-12 short bullets describing what you changed
  "warnings": [string, ...],              // 0-10 warnings (missing info, unclear metrics, risky claims)
  "confidence": number                    // 0.0 to 1.0
}

IMPORTANT RULES:
- "ats_keywords" must be job-relevant terms from the JD (tools, skills, methods, domain words)
- "cv_text" must preserve the candidate facts, but can reorder, rewrite, and strengthen bullets
- Make keyword usage natural; no keyword stuffing
- If the job requires something not in the CV, keep it in "warnings" instead of faking it

CANDIDATE CV (SOURCE):
"""
${cvText}
"""

JOB DESCRIPTION (SOURCE):
"""
${jobDescription}
"""
  `.trim();
}

// -----------------------------
// Gemini (AI Studio + Vertex fallback)
// -----------------------------
function getAiStudioKey(env) {
  return String(env.GEMINI_AI_STUDIO_API_KEY || env.GOOGLE_AI_API_KEY || env.GEMINI_API_KEY || "").trim();
}

function getVertexProjectId(env) {
  const v = String(env.GEMINI_VERTEX_PROJECT_ID || env.VERTEX_PROJECT_ID || env.GCP_PROJECT_ID || "").trim();
  if (v) return v;
  try {
    const raw = String(env.GCP_SA_KEY_JSON || "").trim();
    if (raw) {
      const sa = JSON.parse(raw);
      if (sa?.project_id) return String(sa.project_id);
    }
  } catch {}
  return "";
}

function getVertexLocation(env) {
  let loc = String(env.GEMINI_VERTEX_LOCATION || env.VERTEX_LOCATION || env.GEMINI_LOCATION || "").trim();
  if (!loc) loc = "us-central1";
  return loc;
}

let __gcpTokenCache = { token: null, exp: 0 };

async function getGcpAccessTokenCached(env) {
  const now = Math.floor(Date.now() / 1000);
  if (__gcpTokenCache.token && now < (__gcpTokenCache.exp - 60)) return __gcpTokenCache.token;
  const token = await getGcpAccessToken(env);
  __gcpTokenCache.token = token;
  __gcpTokenCache.exp = now + 3300;
  return token;
}

async function fetchJsonWithRetry(url, options, { label, retries = 2, baseDelayMs = 650, maxDelayMs = 8000 } = {}) {
  let attempt = 0;
  while (true) {
    const res = await fetch(url, options);
    const txt = await res.text().catch(() => "");
    let data = null;
    try { data = txt ? JSON.parse(txt) : null; } catch { data = null; }

    if (res.ok) return { res, txt, data };

    const status = res.status;
    const isRetriable = status === 429 || status === 500 || status === 502 || status === 503 || status === 504;
    if (isRetriable && attempt < retries) {
      const jitter = Math.floor(Math.random() * 250);
      const delay = Math.min(maxDelayMs, baseDelayMs * Math.pow(2, attempt)) + jitter;
      await sleep(delay);
      attempt += 1;
      continue;
    }
    throw new Error(`${label} ${status}: ${(txt || "").slice(0, 1200)}`);
  }
}

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

function parseModelList(value, fallback = []) {
  const raw = Array.isArray(value) ? value : String(value || "").split(",");
  const out = [];
  const seen = new Set();
  const add = (m) => {
    const v = String(m || "").trim();
    if (!v) return;
    const k = v.toLowerCase();
    if (seen.has(k)) return;
    seen.add(k);
    out.push(v);
  };
  for (const m of raw) add(m);
  for (const m of (Array.isArray(fallback) ? fallback : [fallback])) add(m);
  return out;
}

async function geminiGenerateJsonWithModels(env, { models, promptText, temperature = 0.2, maxOutputTokens = 1400 }) {
  const list = parseModelList(models, ["gemini-2.0-flash"]);
  if (!list.length) throw new Error("No Gemini models configured");

  const maxRetries429 = clampInt(env.GEMINI_RETRY_429, 0, 6, 2);
  const baseDelayMs = clampInt(env.GEMINI_RETRY_BASE_MS, 200, 4000, 650);

  let lastErr = null;

  for (const model of list) {
    let tokens = Number(maxOutputTokens) || 1400;

    for (let attempt = 0; attempt <= maxRetries429; attempt++) {
      try {
        const text = await geminiGenerateJson(env, { model, promptText, temperature, maxOutputTokens: tokens });
        const parsed = safeJsonParse(text);
        return { model, parsed, rawText: text };
      } catch (e) {
        lastErr = e;
        const msg = String(e?.message || e || "");
        const is429 = msg.includes(" 429") || /RESOURCE_EXHAUSTED/i.test(msg) || /rate\s*limit/i.test(msg);

        if (attempt < maxRetries429 && is429) {
          const jitter = Math.floor(Math.random() * 250);
          const delay = baseDelayMs * Math.pow(2, attempt) + jitter;
          await sleep(delay);
          continue;
        }
        break;
      }
    }
  }

  throw lastErr || new Error("Gemini failed");
}

async function geminiGenerateJson(env, { model, promptText, temperature = 0.2, maxOutputTokens = 700 }) {
  const prefer = String(env.GEMINI_API_BASE || "auto").trim().toLowerCase();

  const payload = {
    contents: [{ role: "user", parts: [{ text: promptText }] }],
    generationConfig: {
      temperature,
      maxOutputTokens,
      responseMimeType: "application/json",
    },
  };

  async function callAiStudioWithApiKey(apiKey) {
    const url =
      `https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(model)}:generateContent` +
      `?key=${encodeURIComponent(apiKey)}`;

    const { data } = await fetchJsonWithRetry(
      url,
      { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload) },
      { label: "AI Studio Gemini error", retries: 1 }
    );

    return data?.candidates?.[0]?.content?.parts?.map((p) => p.text || "").join("") || "";
  }

  async function callVertex() {
    const project = getVertexProjectId(env);
    const location = getVertexLocation(env);
    if (!project) throw new Error("Vertex Gemini misconfigured: missing GEMINI_VERTEX_PROJECT_ID (or GCP_PROJECT_ID)");
    if (!String(env.GCP_SA_KEY_JSON || "").trim()) throw new Error("Vertex Gemini misconfigured: missing GCP_SA_KEY_JSON");

    const accessToken = await getGcpAccessTokenCached(env);
    const host = `${location}-aiplatform.googleapis.com`;

    const url =
      `https://${host}/v1/projects/${encodeURIComponent(project)}` +
      `/locations/${encodeURIComponent(location)}` +
      `/publishers/google/models/${encodeURIComponent(model)}:generateContent`;

    const { data } = await fetchJsonWithRetry(
      url,
      {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${accessToken}` },
        body: JSON.stringify(payload),
      },
      { label: "Vertex Gemini error", retries: 2 }
    );

    return data?.candidates?.[0]?.content?.parts?.map((p) => p.text || "").join("") || "";
  }

  const key = getAiStudioKey(env);

  if (prefer === "aistudio") {
    if (!key) throw new Error("AI Studio Gemini misconfigured: set GEMINI_API_KEY");
    return await callAiStudioWithApiKey(key);
  }

  if (prefer === "vertex") {
    return await callVertex();
  }

  // auto: try Vertex if configured, else AI Studio
  if (String(env.GCP_SA_KEY_JSON || "").trim()) {
    try {
      return await callVertex();
    } catch (_) {
      // fallback to AI Studio if present
    }
  }

  if (!key) throw new Error("Gemini misconfigured: set GEMINI_API_KEY (or configure Vertex with GCP_SA_KEY_JSON)");
  return await callAiStudioWithApiKey(key);
}

// --- OAuth token for Vertex (service account) ---
function base64UrlEncode(bytes) {
  const bin = String.fromCharCode(...bytes);
  const b64 = btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  return b64;
}

function pemToArrayBuffer(pem) {
  const b64 = pem.replace(/-----BEGIN PRIVATE KEY-----/g, "")
    .replace(/-----END PRIVATE KEY-----/g, "")
    .replace(/\s+/g, "");
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes.buffer;
}

async function signJwtRS256(privateKeyPem, headerObj, payloadObj) {
  const enc = new TextEncoder();
  const header = base64UrlEncode(enc.encode(JSON.stringify(headerObj)));
  const payload = base64UrlEncode(enc.encode(JSON.stringify(payloadObj)));
  const data = `${header}.${payload}`;

  const keyBuf = pemToArrayBuffer(privateKeyPem);
  const cryptoKey = await crypto.subtle.importKey(
    "pkcs8",
    keyBuf,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["sign"]
  );

  const sigBuf = await crypto.subtle.sign({ name: "RSASSA-PKCS1-v1_5" }, cryptoKey, enc.encode(data));
  const sig = base64UrlEncode(new Uint8Array(sigBuf));
  return `${data}.${sig}`;
}

async function getGcpAccessToken(env) {
  const raw = String(env.GCP_SA_KEY_JSON || "").trim();
  if (!raw) throw new Error("Missing GCP_SA_KEY_JSON");
  const saJson = JSON.parse(raw);

  const clientEmail = saJson.client_email;
  const privateKey = saJson.private_key;
  if (!clientEmail || !privateKey) throw new Error("GCP_SA_KEY_JSON missing client_email/private_key");

  const now = Math.floor(Date.now() / 1000);
  const header = { alg: "RS256", typ: "JWT" };
  const payload = {
    iss: clientEmail,
    scope: "https://www.googleapis.com/auth/cloud-platform",
    aud: "https://oauth2.googleapis.com/token",
    iat: now,
    exp: now + 3600,
  };

  const assertion = await signJwtRS256(privateKey, header, payload);

  const form = new URLSearchParams();
  form.set("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer");
  form.set("assertion", assertion);

  const res = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: form.toString(),
  });

  const txt = await res.text().catch(() => "");
  if (!res.ok) throw new Error(`GCP token error ${res.status}: ${txt}`);
  const data = txt ? JSON.parse(txt) : null;
  if (!data?.access_token) throw new Error(`GCP token missing access_token: ${txt}`);
  return data.access_token;
}

// -----------------------------
// Output normalization + helpers
// -----------------------------
function normalizeTailorOutput(obj) {
  const o = (obj && typeof obj === "object") ? obj : {};
  const language = String(o.language || "").trim().toLowerCase();

  return {
    language: (language === "de" || language === "en") ? language : null,
    ats_keywords: Array.isArray(o.ats_keywords) ? o.ats_keywords : (Array.isArray(o.keywords) ? o.keywords : []),
    cv_text: String(o.cv_text || o.tailored_cv || o.cv || "").trim(),
    changes: Array.isArray(o.changes) ? o.changes : [],
    warnings: Array.isArray(o.warnings) ? o.warnings : [],
    confidence: typeof o.confidence === "number" ? o.confidence : null,
  };
}

function safeJsonParse(text) {
  const raw = String(text || "").trim();
  if (!raw) throw new Error("EMPTY_OUTPUT");

  // Remove common markdown fences if present
  let t = raw;
  if (t.startsWith("```")) {
    t = t.replace(/^```[a-zA-Z]*\s*/g, "").replace(/```$/g, "").trim();
  }

  // Try direct parse
  try {
    return JSON.parse(t);
  } catch {}

  // Try extract first JSON object
  const first = t.indexOf("{");
  const last = t.lastIndexOf("}");
  if (first >= 0 && last > first) {
    const chunk = t.slice(first, last + 1);
    try {
      return JSON.parse(chunk);
    } catch {}
  }

  throw new Error("BAD_JSON");
}

function dedupeStrings(arr) {
  const out = [];
  const seen = new Set();
  for (const v of (Array.isArray(arr) ? arr : [])) {
    const s = String(v || "").trim();
    if (!s) continue;
    const k = s.toLowerCase();
    if (seen.has(k)) continue;
    seen.add(k);
    out.push(s);
  }
  return out;
}

function keywordInText(hayLower, keyword) {
  const kw = String(keyword || "").trim().toLowerCase();
  if (!kw || kw.length < 2) return false;

  // If keyword has special chars, just use includes
  if (/[^a-z0-9\s-]/i.test(kw)) return hayLower.includes(kw);

  // Phrase -> includes
  if (kw.includes(" ")) return hayLower.includes(kw);

  // Single word -> word boundary
  const re = new RegExp(`\\b${escapeRegExp(kw)}\\b`, "i");
  return re.test(hayLower);
}

function escapeRegExp(s) {
  return String(s).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function normalizeStrength(v) {
  const s = String(v ?? "").trim().toLowerCase();
  if (s === "0" || s === "light") return "light";
  if (s === "2" || s === "strong") return "strong";
  return "balanced";
}

function normalizeLanguageHint(v) {
  const s = String(v ?? "").trim().toLowerCase();
  if (s === "en" || s === "english") return "en";
  if (s === "de" || s === "german") return "de";
  return "auto";
}

function clamp(n, min, max) {
  const x = Number(n);
  if (!Number.isFinite(x)) return min;
  return Math.min(Math.max(x, min), max);
}

function clampInt(val, min, max, fallback) {
  const n = Number.parseInt(String(val ?? ""), 10);
  if (Number.isNaN(n)) return fallback;
  if (n < min) return min;
  if (n > max) return max;
  return n;
}

async function sha256Hex(input) {
  const data = new TextEncoder().encode(String(input ?? ""));
  const hashBuf = await crypto.subtle.digest("SHA-256", data);
  const hashArr = Array.from(new Uint8Array(hashBuf));
  return hashArr.map((b) => b.toString(16).padStart(2, "0")).join("");
}

// -----------------------------
// Anon tracking (KV)
// -----------------------------
function mustKv(env) {
  const kv = env.ANON_KV;
  if (!kv) throw new Error("Missing KV binding: ANON_KV");
  return kv;
}

function getFreeLimit(env) {
  return clampInt(env.FREE_TAILOR_LIMIT, 0, 1000, 3);
}

function usageTtlSeconds(env) {
  const days = clampInt(env.ANON_USAGE_TTL_DAYS, 7, 365, 90);
  return days * 24 * 60 * 60;
}

async function readAnonUsage(kv, anonId, env) {
  const key = `anon:${anonId}:usage`;
  const obj = await kv.get(key, "json").catch(() => null);
  if (obj && typeof obj === "object") {
    return {
      tailor_count: clampInt(obj.tailor_count, 0, 1000000, 0),
      first_at: obj.first_at || null,
      last_at: obj.last_at || null,
    };
  }
  return { tailor_count: 0, first_at: null, last_at: null };
}

async function incrementAnonUsage(kv, anonId, env) {
  const key = `anon:${anonId}:usage`;
  const now = new Date().toISOString();
  const ttl = usageTtlSeconds(env);

  const cur = await readAnonUsage(kv, anonId, env);
  const next = {
    tailor_count: (cur.tailor_count || 0) + 1,
    first_at: cur.first_at || now,
    last_at: now,
  };

  await kv.put(key, JSON.stringify(next), { expirationTtl: ttl }).catch(() => {});
}

// -----------------------------
// Anon ID (cookie + header friendly)
// -----------------------------
function getOrCreateAnonId(request) {
  const headerId = String(request.headers.get("x-anon-id") || "").trim();
  if (looksLikeUuid(headerId)) {
    return { anonId: headerId, setCookie: null, source: "header" };
  }

  const cookieId = getCookie(request, "cvstudio_anon");
  if (looksLikeUuid(cookieId)) {
    return { anonId: cookieId, setCookie: null, source: "cookie" };
  }

  const anonId = crypto?.randomUUID ? crypto.randomUUID() : fallbackUuid();
  const cookie = makeCookie("cvstudio_anon", anonId, {
    maxAgeSec: 60 * 60 * 24 * 365,
    path: "/",
    secure: true,
    httpOnly: true,
    sameSite: "Lax",
  });

  return { anonId, setCookie: cookie, source: "new" };
}

function fallbackUuid() {
  // Not perfect, but fine as fallback
  const s = () => Math.floor((1 + Math.random()) * 0x10000).toString(16).slice(1);
  return `${s()}${s()}-${s()}-${s()}-${s()}-${s()}${s()}${s()}`;
}

function looksLikeUuid(s) {
  return /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$/.test(String(s || ""));
}

function getCookie(request, name) {
  const cookie = request.headers.get("Cookie") || "";
  const parts = cookie.split(";").map((p) => p.trim());
  for (const p of parts) {
    if (!p) continue;
    const idx = p.indexOf("=");
    if (idx < 0) continue;
    const k = p.slice(0, idx).trim();
    const v = p.slice(idx + 1).trim();
    if (k === name) return decodeURIComponent(v);
  }
  return "";
}

function makeCookie(name, value, opts = {}) {
  const parts = [];
  parts.push(`${name}=${encodeURIComponent(String(value))}`);
  parts.push(`Path=${opts.path || "/"}`);
  if (opts.maxAgeSec) parts.push(`Max-Age=${Math.floor(opts.maxAgeSec)}`);
  if (opts.httpOnly) parts.push("HttpOnly");
  if (opts.secure) parts.push("Secure");
  parts.push(`SameSite=${opts.sameSite || "Lax"}`);
  return parts.join("; ");
}

// -----------------------------
// CORS + JSON response helpers
// -----------------------------
function corsHeaders(request, env) {
  const origin = request.headers.get("Origin") || "";
  const allowlist = String(env.CORS_ORIGINS || "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);

  // Default: permissive (good for early growth); tighten later.
  let allowOrigin = "*";
  if (origin) {
    if (!allowlist.length) allowOrigin = origin;
    else if (allowlist.includes("*") || allowlist.includes(origin)) allowOrigin = origin;
    else allowOrigin = allowlist[0] || origin;
  }

  const reqHeaders = request.headers.get("Access-Control-Request-Headers") || "";
  const allowHeaders = reqHeaders || "Content-Type, Authorization, x-anon-id";

  return {
    "Access-Control-Allow-Origin": allowOrigin,
    "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
    "Access-Control-Allow-Headers": allowHeaders,
    "Access-Control-Max-Age": "86400",
    "Vary": "Origin, Access-Control-Request-Headers",
  };
}

function json(request, env, body, status = 200, extraHeaders = {}) {
  const headers = {
    "Content-Type": "application/json; charset=utf-8",
    ...corsHeaders(request, env),
    ...extraHeaders,
  };
  return new Response(JSON.stringify(body), { status, headers });
}
