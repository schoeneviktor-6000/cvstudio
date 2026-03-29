/* auth.js - Shared Supabase + CV Studio auth helpers
IMPORTANT:
- Load AFTER: ./vendor/supabase-js-2.100.1.js
- This is a plain JS file (NO <script> tags)
*/
(() => {
"use strict";

/* ============================================================
1) Defaults (frontend-safe)
============================================================ */
const SUPABASE_URL_DEFAULT = "https://awlzvhcnjegfhjedswko.supabase.co";

// Supabase ANON key (public, safe to ship to browser)
const SUPABASE_ANON_KEY_DEFAULT =
"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImF3bHp2aGNuamVnZmhqZWRzd2tvIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NjY2NTE2OTgsImV4cCI6MjA4MjIyNzY5OH0.-UmHiVi0_g9tKDkr6ldfROeBrOk8hm18YVPRfnb8luY";

// Your Worker API base (default)
const API_BASE_DEFAULT = "https://jobmejob.schoene-viktor.workers.dev";

/* ============================================================
2) Safe localStorage helpers
============================================================ */
function lsGet(key) {
  try { return localStorage.getItem(key); } catch { return null; }
}
function lsSet(key, val) {
  try { localStorage.setItem(key, val); } catch {}
}
function lsRemove(key) {
  try { localStorage.removeItem(key); } catch {}
}
function lsKeys() {
  try {
    const out = [];
    for (let i = 0; i < localStorage.length; i += 1) {
      const k = localStorage.key(i);
      if (k) out.push(k);
    }
    return out;
  } catch {
    return [];
  }
}

function ssKeys() {
  try {
    const out = [];
    for (let i = 0; i < sessionStorage.length; i += 1) {
      const k = sessionStorage.key(i);
      if (k) out.push(k);
    }
    return out;
  } catch {
    return [];
  }
}

function ssGet(key) {
  try { return sessionStorage.getItem(key); } catch { return null; }
}

function ssSet(key, val) {
  try { sessionStorage.setItem(key, val); } catch {}
}

function ssRemove(key) {
  try { sessionStorage.removeItem(key); } catch {}
}

function isLocalDebugHost() {
  try {
    const host = String(window.location.hostname || "").trim().toLowerCase();
    const protocol = String(window.location.protocol || "").trim().toLowerCase();
    return (
      protocol === "file:" ||
      host === "localhost" ||
      host.endsWith(".localhost") ||
      host === "0.0.0.0" ||
      host === "::1" ||
      host === "[::1]" ||
      /^127(?:\.\d{1,3}){3}$/.test(host)
    );
  } catch {
    return false;
  }
}

function isAppStorageKey(key) {
  const k = String(key || "");
  return (
    k === "sb_access_token" ||
    k.startsWith("ja_") ||
    k.startsWith("jm_") ||
    k.startsWith("jmj_") ||
    k.startsWith("jobmejob_") ||
    k.startsWith("jobapplyai_") ||
    k.startsWith("cvstudio_") ||
    k.startsWith("jobs_") ||
    k.startsWith("tailor_") ||
    k.startsWith("cv_")
  );
}

/* ============================================================
3) Config resolution (NO duplicate consts)
- sb_url / sb_anon can be overridden in localStorage for debugging
- jm_api_base can override API base for debugging
- Still falls back to legacy ja_api_base for older local setups
- Also supports window.JobMeJob.config.API_BASE if already set by page
============================================================ */
const CAN_USE_DEBUG_OVERRIDES = isLocalDebugHost();
const SUPABASE_URL = CAN_USE_DEBUG_OVERRIDES
  ? ((lsGet("sb_url") || "").trim() || SUPABASE_URL_DEFAULT)
  : SUPABASE_URL_DEFAULT;
const SUPABASE_ANON_KEY = CAN_USE_DEBUG_OVERRIDES
  ? ((lsGet("sb_anon") || "").trim() || SUPABASE_ANON_KEY_DEFAULT)
  : SUPABASE_ANON_KEY_DEFAULT;

// Debug override: localStorage.setItem("jm_api_base","http://localhost:8787")
const apiOverride = CAN_USE_DEBUG_OVERRIDES
  ? ((lsGet("jm_api_base") || lsGet("ja_api_base") || "").trim().replace(/\/+$/, ""))
  : "";

// If the page already defined a base (some pages do), reuse it
const appConfig =
  (window.CVStudio && window.CVStudio.config)
    ? window.CVStudio.config
    : ((window.JobMeJob && window.JobMeJob.config)
      ? window.JobMeJob.config
      : ((window.JobApplyAI && window.JobApplyAI.config) ? window.JobApplyAI.config : null));
const apiFromWindow =
  (appConfig && appConfig.API_BASE)
    ? String(appConfig.API_BASE).trim().replace(/\/+$/, "")
    : "";

const API_BASE = apiOverride || apiFromWindow || API_BASE_DEFAULT;

const GOOGLE_PROVIDER_TOKEN_KEY = "jm_google_provider_token";
const GOOGLE_PROVIDER_REFRESH_TOKEN_KEY = "jm_google_provider_refresh_token";
const GOOGLE_PROVIDER_SCOPE_KEY = "jm_google_provider_scope";
const GOOGLE_PROVIDER_UPDATED_AT_KEY = "jm_google_provider_updated_at";
const POST_AUTH_REDIRECT_KEY = "jm_post_auth_redirect_v1";
const POST_AUTH_REDIRECT_MAX_AGE_MS = 30 * 60 * 1000;

/* ============================================================
4) Create Supabase client
============================================================ */
if (!window.supabase || typeof window.supabase.createClient !== "function") {
  console.error("[auth.js] supabase-js is not loaded. Include ./vendor/supabase-js-2.100.1.js BEFORE auth.js");
  return;
}

const supabaseClient = window.supabase.createClient(SUPABASE_URL, SUPABASE_ANON_KEY, {
  auth: { persistSession: true, autoRefreshToken: true, detectSessionInUrl: true }
});

// Backward compatibility: some pages reference window.supabaseClient
window.supabaseClient = supabaseClient;

function cacheGoogleProviderTokens(session) {
  try {
    const s = session && typeof session === "object" ? session : null;
    const providerToken = s && typeof s.provider_token === "string" ? s.provider_token.trim() : "";
    const providerRefreshToken = s && typeof s.provider_refresh_token === "string" ? s.provider_refresh_token.trim() : "";

    if (providerToken) {
      ssSet(GOOGLE_PROVIDER_TOKEN_KEY, providerToken);
      ssSet(GOOGLE_PROVIDER_UPDATED_AT_KEY, new Date().toISOString());
    }
    if (providerRefreshToken) {
      ssSet(GOOGLE_PROVIDER_REFRESH_TOKEN_KEY, providerRefreshToken);
    }
    if (providerToken || providerRefreshToken) {
      const scope = (ssGet("jm_google_oauth_scope_request") || "").trim();
      if (scope) ssSet(GOOGLE_PROVIDER_SCOPE_KEY, scope);
    }
  } catch {}
}

function clearGoogleProviderTokens() {
  ssRemove(GOOGLE_PROVIDER_TOKEN_KEY);
  ssRemove(GOOGLE_PROVIDER_REFRESH_TOKEN_KEY);
  ssRemove(GOOGLE_PROVIDER_SCOPE_KEY);
  ssRemove(GOOGLE_PROVIDER_UPDATED_AT_KEY);
  ssRemove("jm_google_oauth_scope_request");
}

function normalizePostAuthRedirect(input) {
  try {
    const raw = String(input || "").trim();
    if (!raw) return "";
    const url = new URL(raw, window.location.origin);
    if (url.origin !== window.location.origin) return "";
    return `${url.pathname}${url.search}${url.hash}`;
  } catch {
    return "";
  }
}

function rememberPostAuthRedirect(url) {
  try {
    const normalized = normalizePostAuthRedirect(url);
    if (!normalized) return false;
    lsSet(POST_AUTH_REDIRECT_KEY, JSON.stringify({
      url: normalized,
      created_at: Date.now()
    }));
    return true;
  } catch {
    return false;
  }
}

function peekPostAuthRedirect() {
  try {
    const raw = lsGet(POST_AUTH_REDIRECT_KEY);
    if (!raw) return "";
    const parsed = JSON.parse(raw);
    const createdAt = Number(parsed && parsed.created_at ? parsed.created_at : 0);
    if (!createdAt || (Date.now() - createdAt) > POST_AUTH_REDIRECT_MAX_AGE_MS) {
      lsRemove(POST_AUTH_REDIRECT_KEY);
      return "";
    }
    const normalized = normalizePostAuthRedirect(parsed && parsed.url ? parsed.url : "");
    if (!normalized) {
      lsRemove(POST_AUTH_REDIRECT_KEY);
      return "";
    }
    return normalized;
  } catch {
    lsRemove(POST_AUTH_REDIRECT_KEY);
    return "";
  }
}

function consumePostAuthRedirect() {
  const url = peekPostAuthRedirect();
  if (url) lsRemove(POST_AUTH_REDIRECT_KEY);
  return url;
}

supabaseClient.auth.onAuthStateChange((_event, session) => {
  if (!session) {
    clearGoogleProviderTokens();
    return;
  }
  cacheGoogleProviderTokens(session);
});

/* ============================================================
5) Auth helpers
============================================================ */
async function getSession() {
  const { data, error } = await supabaseClient.auth.getSession();
  if (error) return null;
  return data && data.session ? data.session : null;
}

async function requireSession(redirectTo = "./signup.html") {
  const session = await getSession();
  if (!session || !session.user || !session.user.email) {
    if (redirectTo) window.location.replace(redirectTo);
    return null;
  }
  return session;
}

async function loginWithGoogle(redirectToOrOptions, maybeOptions) {
  const opts = (redirectToOrOptions && typeof redirectToOrOptions === "object")
    ? redirectToOrOptions
    : { ...(maybeOptions || {}), redirectTo: redirectToOrOptions };
  const rt = opts.redirectTo || (window.location.origin + window.location.pathname);
  const oauthOptions = { redirectTo: rt };

  if (opts.scopes) {
    oauthOptions.scopes = String(opts.scopes);
  }
  if (opts.queryParams && typeof opts.queryParams === "object") {
    oauthOptions.queryParams = opts.queryParams;
  }
  if (oauthOptions.scopes) {
    ssSet("jm_google_oauth_scope_request", oauthOptions.scopes);
  } else {
    ssRemove("jm_google_oauth_scope_request");
  }

  const { error } = await supabaseClient.auth.signInWithOAuth({
    provider: "google",
    options: oauthOptions
  });
  if (error) throw error;
}

async function logout(redirectTo = "./index.html") {
  try { await supabaseClient.auth.signOut(); } catch {}

  // Clean app-owned caches and view state, but let supabase-js own its session keys.
  for (const k of lsKeys()) {
    if (isAppStorageKey(k)) lsRemove(k);
  }
  for (const k of ssKeys()) {
    if (isAppStorageKey(k)) ssRemove(k);
  }

  if (redirectTo) window.location.replace(redirectTo);
}

/* ============================================================
6) Backend helper: ensure customer exists
============================================================ */
async function upsertCustomerByEmail(email) {
  const res = await fetch(`${API_BASE}/customers/upsert`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ email })
  });

  const text = await res.text().catch(() => "");
  if (!res.ok) throw new Error(`Customer upsert failed: ${res.status} ${text}`);
  return JSON.parse(text);
}

// Ensures customer row exists for the logged-in user
async function requireAuthAndCustomer(opts = {}) {
  const redirectTo = opts.redirectTo || "./signup.html";
  const session = await requireSession(redirectTo);
  if (!session) return null;

  const email = String(session.user.email || "").trim().toLowerCase();
  if (!email) {
    if (redirectTo) window.location.replace(redirectTo);
    return null;
  }

  const data = await upsertCustomerByEmail(email);
  const customerId = data && data.customer_id ? String(data.customer_id).trim() : "";

  if (customerId) lsSet("jm_customer_id", customerId);
  lsSet("jm_user_email", email);

  return { session, email, customerId: customerId || null };
}

// Optional: align local flags with backend truth (good for new device/incognito)
async function syncStateToLocalStorage(session) {
  try {
    const token = session && session.access_token ? session.access_token : "";
    if (!token) return null;

    const res = await fetch(`${API_BASE}/me/state`, {
      method: "GET",
      headers: { Authorization: `Bearer ${token}` }
    });
    if (!res.ok) return null;

    const state = await res.json();

    if (state && state.customer_id) lsSet("jm_customer_id", String(state.customer_id));
    if (state && state.email) lsSet("jm_user_email", String(state.email).trim().toLowerCase());

    if (state && state.plan_id) lsSet("jm_plan", String(state.plan_id).trim().toLowerCase());
    else lsRemove("jm_plan");

    if (state && state.profile_complete) lsSet("jm_profile_complete", "true");
    else lsRemove("jm_profile_complete");

    return state;
  } catch {
    return null;
  }
}

/* ============================================================
7) Export API for existing pages
============================================================ */
const app = window.CVStudio || window.JobMeJob || window.JobApplyAI || {};
window.CVStudio = app;
window.JobMeJob = app;
window.JobApplyAI = app;

app.config = app.config || {};
app.config.API_BASE = API_BASE;
app.config.SUPABASE_URL = SUPABASE_URL;
app.config.CAN_USE_DEBUG_OVERRIDES = CAN_USE_DEBUG_OVERRIDES;

app.auth = {
  supabaseClient,
  getSession,
  requireSession,
  loginWithGoogle,
  cacheGoogleProviderTokens,
  getCachedGoogleProviderToken: () => ssGet(GOOGLE_PROVIDER_TOKEN_KEY) || "",
  getCachedGoogleProviderRefreshToken: () => ssGet(GOOGLE_PROVIDER_REFRESH_TOKEN_KEY) || "",
  getCachedGoogleProviderScope: () => ssGet(GOOGLE_PROVIDER_SCOPE_KEY) || "",
  clearGoogleProviderTokens,
  rememberPostAuthRedirect,
  peekPostAuthRedirect,
  consumePostAuthRedirect,
  logout,
  requireAuthAndCustomer,
  syncStateToLocalStorage
};
})();
