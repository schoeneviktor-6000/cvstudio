/**
 * Cloudflare Pages Function: POST /api/tailor
 *
 * Strategy:
 * - 3 free tailorings without login (configurable via FREE_TAILOR_LIMIT)
 * - Track anonymous usage via KV (binding: ANON_KV)
 * - Cache identical requests for a short time to avoid burning free runs on refresh
 * - Call Gemini (AI Studio Generative Language API) and return JSON result
 *
 * Required bindings:
 * - ANON_KV (KV namespace)
 *
 * Required env:
 * - GEMINI_API_KEY (AI Studio API key)
 *
 * Optional env:
 * - FREE_TAILOR_LIMIT (default 3)
 * - CACHE_SECONDS (default 3600)
 * - ANON_USAGE_TTL_DAYS (default 90)
 * - ANON_COOLDOWN_MS (default 15000)
 */

export async function onRequestPost(context) {
  const { request, env } = context;

  // CORS + preflight handled by Pages, but we still return proper headers
  const cors = corsHeaders(request, env);

  let body;
  try {
    body = await request.json();
  } catch {
    return json({ ok: false, code: "BAD_REQUEST", message: "Invalid JSON body." }, 400, cors);
  }

  const cvTextRaw = String(body?.cvText || body?.cv_text || body?.cv || "").trim();
  const jdTextRaw = String(body?.jdText || body?.job_description || body?.jd || "").trim();

  if (cvTextRaw.length < 120) {
    return json({ ok: false, code: "BAD_REQUEST", message: "Please provide a CV (min ~120 characters)." }, 400, cors);
  }
  if (jdTextRaw.length < 80) {
    return json({ ok: false, code: "BAD_REQUEST", message: "Please paste a job description (min ~80 characters)." }, 400, cors);
  }

  if (!env.ANON_KV) {
    return json({ ok: false, code: "SERVER_ERROR", message: "Missing KV binding ANON_KV." }, 500, cors);
  }

  const anon = getOrCreateAnonId(request);
  const freeLimit = clampInt(env.FREE_TAILOR_LIMIT, 0, 1000, 3);

  // Cooldown anti-spam
  const cooldownMs = clampInt(env.ANON_COOLDOWN_MS, 0, 120000, 15000);
  if (cooldownMs > 0) {
    const cdKey = `anon:${anon.id}:cooldown`;
    const last = Number(await env.ANON_KV.get(cdKey).catch(() => "0")) || 0;
    const now = Date.now();
    if (last && now - last < cooldownMs) {
      return json(
        { ok: false, code: "RATE_LIMIT", message: "Please wait a moment and try again.", retry_after_ms: cooldownMs - (now - last) },
        429,
        { ...cors, ...(anon.setCookie ? { "Set-Cookie": anon.setCookie } : {}) }
      );
    }
    await env.ANON_KV.put(cdKey, String(now), { expirationTtl: Math.ceil(cooldownMs / 1000) + 10 }).catch(() => {});
  }

  // Usage check
  const usageKey = `anon:${anon.id}:usage`;
  const usage = await readUsage(env.ANON_KV, usageKey);

  if (freeLimit > 0 && usage.tailor_count >= freeLimit) {
    return json(
      {
        ok: false,
        code: "PAYWALL",
        message: "You’ve used all free CV tailorings. Create an account to continue and unlock downloads.",
        free_limit: freeLimit,
        used: usage.tailor_count,
        remaining_free: 0
      },
      402,
      { ...cors, ...(anon.setCookie ? { "Set-Cookie": anon.setCookie } : {}) }
    );
  }

  // Cache identical requests (refresh-safe)
  const promptVersion = "cvstudio_tailor_prompt_v1";
  const cvText = cvTextRaw.slice(0, 22000);
  const jdText = jdTextRaw.slice(0, 60000);
  const inputHash = await sha256Hex([promptVersion, cvText, jdText].join("|"));
  const cacheKey = `cache:tailor:${inputHash}`;

  const cached = await env.ANON_KV.get(cacheKey, "json").catch(() => null);
  if (cached?.result?.tailored_cv) {
    // Do not increment usage on cache hit
    const remaining = freeLimit <= 0 ? null : Math.max(0, freeLimit - usage.tailor_count);
    return json(
      {
        ok: true,
        cached: true,
        anon_id: anon.id,
        free_limit: freeLimit <= 0 ? "unlimited" : freeLimit,
        used: usage.tailor_count,
        remaining_free: remaining,
        result: cached.result
      },
      200,
      { ...cors, ...(anon.setCookie ? { "Set-Cookie": anon.setCookie } : {}) }
    );
  }

  // Call Gemini
  const apiKey = String(env.GEMINI_API_KEY || "").trim();
  if (!apiKey) {
    return json({ ok: false, code: "SERVER_ERROR", message: "Missing GEMINI_API_KEY env var." }, 500, cors);
  }

  const prompt = buildPrompt({ cvText, jdText });

  const geminiResp = await callGeminiJson(apiKey, prompt);
  const result = normalizeResult(geminiResp, cvText);

  // Store cache
  const cacheSeconds = clampInt(env.CACHE_SECONDS, 60, 86400, 3600);
  await env.ANON_KV.put(cacheKey, JSON.stringify({ result, created_at: new Date().toISOString() }), { expirationTtl: cacheSeconds }).catch(() => {});

  // Increment usage on real generation
  await incrementUsage(env.ANON_KV, usageKey, env);

  const usageAfter = await readUsage(env.ANON_KV, usageKey);
  const remainingAfter = freeLimit <= 0 ? null : Math.max(0, freeLimit - usageAfter.tailor_count);

  return json(
    {
      ok: true,
      cached: false,
      anon_id: anon.id,
      free_limit: freeLimit <= 0 ? "unlimited" : freeLimit,
      used: usageAfter.tailor_count,
      remaining_free: remainingAfter,
      result
    },
    200,
    { ...cors, ...(anon.setCookie ? { "Set-Cookie": anon.setCookie } : {}) }
  );
}

/* -----------------------------
   Gemini call + prompt
-------------------------------- */

function buildPrompt({ cvText, jdText }) {
  return `
You are CVStudio: an expert corporate CV writer and ATS optimization specialist.

Task:
Tailor the candidate's CV to the job description to maximize ATS match and recruiter readability.

Strict rules:
- Do NOT invent facts (skills, degrees, employers, titles, years, tools, certifications, achievements).
- If something is not supported by the CV, do not claim it. You may suggest it as "consider adding if true" in warnings.
- Keep output ATS-friendly plain text. No tables, no columns, no images.

Return ONLY valid JSON with this schema:
{
  "tailored_cv": string,
  "ats_keywords": [string, ...],          // 20-35 keywords/phrases from the JD (ATS terms)
  "warnings": [string, ...],              // 0-12 short warnings / improvements
  "edits_summary": [string, ...],         // 6-12 bullets: what you changed
  "suggested_next_steps": [string, ...],  // 4-10 actionable next steps
  "ats_match_estimate": number            // 0-100
}

Candidate CV:
"""
${cvText}
"""

Job Description:
"""
${jdText}
"""
  `.trim();
}

async function callGeminiJson(apiKey, promptText) {
  // Model choice: you can adjust later
  const model = "gemini-1.5-flash";

  const url = `https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(model)}:generateContent?key=${encodeURIComponent(apiKey)}`;

  const payload = {
    contents: [{ role: "user", parts: [{ text: promptText }] }],
    generationConfig: {
      temperature: 0.2,
      maxOutputTokens: 5200,
      responseMimeType: "application/json"
    }
  };

  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload)
  });

  const text = await res.text().catch(() => "");
  if (!res.ok) {
    throw new Error(`Gemini error ${res.status}: ${text.slice(0, 1200)}`);
  }

  let data;
  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    throw new Error(`Gemini returned non-JSON: ${text.slice(0, 1200)}`);
  }

  const outText = data?.candidates?.[0]?.content?.parts?.map((p) => p.text || "").join("") || "";
  const parsed = safeJsonParse(outText);
  return parsed;
}

function safeJsonParse(raw) {
  let t = String(raw || "").trim();
  if (!t) throw new Error("Empty model output.");

  if (t.startsWith("```")) {
    t = t.replace(/^```[a-zA-Z]*\s*/g, "").replace(/```$/g, "").trim();
  }

  try {
    return JSON.parse(t);
  } catch {}

  const first = t.indexOf("{");
  const last = t.lastIndexOf("}");
  if (first >= 0 && last > first) {
    const chunk = t.slice(first, last + 1);
    try {
      return JSON.parse(chunk);
    } catch {}
  }

  throw new Error("Could not parse JSON from model output.");
}

/* -----------------------------
   Result normalization (ATS keyword added/missing)
-------------------------------- */

function normalizeResult(modelObj, originalCvText) {
  const o = (modelObj && typeof modelObj === "object") ? modelObj : {};

  const tailored = String(o.tailored_cv || "").trim();
  const keywords = dedupeStrings(Array.isArray(o.ats_keywords) ? o.ats_keywords : []);
  const warnings = dedupeStrings(Array.isArray(o.warnings) ? o.warnings : []).slice(0, 12);
  const edits = dedupeStrings(Array.isArray(o.edits_summary) ? o.edits_summary : []).slice(0, 12);
  const next = dedupeStrings(Array.isArray(o.suggested_next_steps) ? o.suggested_next_steps : []).slice(0, 10);

  const match = clampInt(o.ats_match_estimate, 0, 100, 60);

  const origLower = String(originalCvText || "").toLowerCase();
  const outLower = tailored.toLowerCase();

  const added = [];
  const missing = [];

  for (const kw of keywords) {
    const inOrig = keywordInText(origLower, kw);
    const inOut = keywordInText(outLower, kw);
    if (!inOrig && inOut) added.push(kw);
    if (!inOut) missing.push(kw);
  }

  return {
    tailored_cv: tailored,
    ats_match_estimate: match,
    ats_keywords_added: added.slice(0, 40),
    missing_keywords: missing.slice(0, 40),
    warnings,
    edits_summary: edits,
    suggested_next_steps: next
  };
}

function keywordInText(hayLower, keyword) {
  const kw = String(keyword || "").trim().toLowerCase();
  if (!kw || kw.length < 2) return false;
  if (/[^a-z0-9\s-]/i.test(kw)) return hayLower.includes(kw);
  if (kw.includes(" ")) return hayLower.includes(kw);
  const re = new RegExp(`\\b${escapeRegExp(kw)}\\b`, "i");
  return re.test(hayLower);
}

function escapeRegExp(s) {
  return String(s).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
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

/* -----------------------------
   KV usage helpers
-------------------------------- */

async function readUsage(kv, key) {
  const obj = await kv.get(key, "json").catch(() => null);
  if (obj && typeof obj === "object") {
    return {
      tailor_count: clampInt(obj.tailor_count, 0, 1000000, 0),
      first_at: obj.first_at || null,
      last_at: obj.last_at || null
    };
  }
  return { tailor_count: 0, first_at: null, last_at: null };
}

async function incrementUsage(kv, key, env) {
  const now = new Date().toISOString();
  const ttl = clampInt(env.ANON_USAGE_TTL_DAYS, 7, 365, 90) * 24 * 60 * 60;

  const cur = await readUsage(kv, key);
  const next = {
    tailor_count: (cur.tailor_count || 0) + 1,
    first_at: cur.first_at || now,
    last_at: now
  };

  await kv.put(key, JSON.stringify(next), { expirationTtl: ttl }).catch(() => {});
}

/* -----------------------------
   Anonymous ID (cookie)
-------------------------------- */

function getOrCreateAnonId(request) {
  const cookieId = getCookie(request, "cvstudio_anon");
  if (looksLikeUuid(cookieId)) return { id: cookieId, setCookie: null };

  const id = crypto.randomUUID();
  const setCookie = makeCookie("cvstudio_anon", id, {
    maxAgeSec: 60 * 60 * 24 * 365,
    path: "/",
    secure: true,
    httpOnly: true,
    sameSite: "Lax"
  });

  return { id, setCookie };
}

function looksLikeUuid(s) {
  return /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$/.test(String(s || ""));
}

function getCookie(request, name) {
  const cookie = request.headers.get("Cookie") || "";
  const parts = cookie.split(";").map((p) => p.trim());
  for (const p of parts) {
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

/* -----------------------------
   Utilities
-------------------------------- */

function corsHeaders(request, env) {
  const origin = request.headers.get("Origin") || "";
  const allowlist = String(env.CORS_ORIGINS || "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);

  let allowOrigin = "*";
  if (origin) {
    if (!allowlist.length) allowOrigin = origin;
    else if (allowlist.includes("*") || allowlist.includes(origin)) allowOrigin = origin;
    else allowOrigin = allowlist[0] || origin;
  }

  return {
    "Access-Control-Allow-Origin": allowOrigin,
    "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
    "Access-Control-Max-Age": "86400",
    "Vary": "Origin"
  };
}

function json(obj, status, headers) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8", ...headers }
  });
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
