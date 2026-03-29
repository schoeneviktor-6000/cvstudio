"use strict";

const S = window.CVStudioShared || window.JobMeJobShared || null;
const APP_CONFIG = window.CVStudio?.config || window.JobMeJob?.config || window.JobApplyAI?.config || null;
function getAppAuth(){
  return window.CVStudio?.auth || window.JobMeJob?.auth || window.JobApplyAI?.auth || null;
}
if (S && S.wireNavTransitions) { try { S.wireNavTransitions(); } catch {} }

const FEATURES = (APP_CONFIG && (APP_CONFIG.FEATURES || APP_CONFIG.features)) || {};
const STANDALONE_MODE = !!(APP_CONFIG && (APP_CONFIG.STANDALONE || APP_CONFIG.standalone || FEATURES.standalone));
const ENABLE_GMAIL = !STANDALONE_MODE && FEATURES.gmail !== false;
const ENABLE_JOB_MATCHING = !STANDALONE_MODE && FEATURES.jobMatching !== false;


const API_BASE = (APP_CONFIG && APP_CONFIG.API_BASE)
  || (S && S.resolveApiBase ? S.resolveApiBase("https://jobmejob.schoene-viktor.workers.dev") : "https://jobmejob.schoene-viktor.workers.dev");
const SUPABASE_URL="https://awlzvhcnjegfhjedswko.supabase.co";
const SUPABASE_ANON_KEY="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImF3bHp2aGNuamVnZmhqZWRzd2tvIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NjY2NTE2OTgsImV4cCI6MjA4MjIyNzY5OH0.-UmHiVi0_g9tKDkr6ldfROeBrOk8hm18YVPRfnb8luY";

const AI_CACHE_KEY="jm_ai_titles_cache_v1";
const AI_CACHE_KEY_OLD="ja_ai_titles_cache_v1";
const GMAIL_VERIFY_RESULT_KEY="jm_gmail_verify_result_v1";
const GMAIL_VERIFY_PENDING_KEY="jm_gmail_verify_pending";
const GMAIL_VERIFY_SCOPE="openid email profile https://www.googleapis.com/auth/gmail.send";

let supabaseClient=null;
let session=null;
let state=null;

let ocrPollTimer=null;

let aiResult=null;
let aiSelectedTitles=new Set();
let aiGeneratedOnce=false;
let aiAppliedOnce=false;
let aiAppliedTitles=[];
let jobTitlesTouched=false;
let locationsTouched=false;
let jobsPrefetchInFlight=false;
let cvLocationHint=[];


let lastCvMeta=null;

let backendAiTitles=[];
let aiAutoStarted=false;
let gmailVerifyInFlight=false;

function $(id){return document.getElementById(id);}
function setText(id,t){const el=$(id);if(el) el.textContent=t;}
function setHtml(id,h){const el=$(id);if(el) el.innerHTML=h;}
function showTopError(msg){
  if (S && S.showTopError) return S.showTopError("errorTop", msg);
  const el=$("errorTop"); if(!el) return; el.style.display="block"; el.textContent=String(msg||"");
}
function clearTopError(){
  if (S && S.showTopError) return S.showTopError("errorTop", "");
  const el=$("errorTop"); if(!el) return; el.style.display="none"; el.textContent="";
}

function applyStandaloneShell(email){
  if(!STANDALONE_MODE) return;
  try{
    const navActivity = $("navActivity");
    if(navActivity) navActivity.style.display = "none";
  }catch(_){}
  try{
    const aiBox = $("aiBox");
    if(aiBox) aiBox.style.display = "none";
  }catch(_){}
  try{
    const gmailBox = $("gmailVerifyBox");
    if(gmailBox) gmailBox.style.display = "none";
  }catch(_){}
  try{
    const prefs = $("prefsCard");
    if(prefs) prefs.style.display = "none";
  }catch(_){}
  try{
    const planVal = $("kPlan");
    const planRow = planVal && planVal.closest ? planVal.closest(".kpiRow") : null;
    if(planRow) planRow.style.display = "none";
  }catch(_){}
  const signed = String(email || "").trim();
  setText("subLine", signed
    ? ("Signed in as " + signed + " - next step: upload your base CV, then open CV Studio.")
    : "Upload your base CV once, then open CV Studio and paste any job description."
  );
}

function escapeHtml(s){
const v=String(s??"");
return v.replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;").replace(/'/g,"&#39;");
}

function setBadge(id,kind,text){
  if (S && S.setBadge) return S.setBadge(id, kind, text);
  const el=$(id);
  if(!el) return;
  el.className="badge"+(kind?(" "+kind):"");
  el.textContent=String(text??"");
}

function go(url){
  if (S && S.go) return S.go(url);
  setTimeout(()=>{window.location.href=url;},180);
}

function isEmail(s){
const v=String(s||"").trim();
return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v);
}

const LS = {
userEmail: ["jm_user_email","ja_user_email"],
customerId: ["jm_customer_id","ja_customer_id"],
profileDone: ["jm_profile_complete","ja_profile_complete"],
plan: ["jm_plan","ja_plan"],
workplace: ["jobmejob_workplace","jobapplyai_workplace"]
};

function lsGetFirst(keys){
for(const k of keys){
const v=localStorage.getItem(k);
if(v !== null && v !== undefined && v !== "") return v;
}
return null;
}
function lsSetAll(keys, value){
const key = Array.isArray(keys) && keys.length ? keys[0] : "";
if(!key) return;
try{ localStorage.setItem(key, value); }catch(_){}
}
function lsRemoveAll(keys){
for(const k of keys){
try{ localStorage.removeItem(k); }catch(_){}
}
}

function resetLocalStateForNewUser(currentEmail){
const last=(lsGetFirst(LS.userEmail)||"").trim().toLowerCase();
const now=(currentEmail||"").trim().toLowerCase();
if(!now) return;
if(last && last!==now){
Object.keys(localStorage).forEach(k=>{
if(k.startsWith("ja_") || k.startsWith("jobapplyai_") || k.startsWith("jm_") || k.startsWith("jobmejob_") || k.startsWith("sb-")){
localStorage.removeItem(k);
}
});
try{sessionStorage.removeItem("sb_access_token");}catch{}
}
lsSetAll(LS.userEmail, now);
}

const FETCH_TIMEOUT_MS = 35000;
const UPLOAD_TIMEOUT_MS = 5 * 60 * 1000; // 5 minutes for mobile uploads
const OCR_STATUS_TIMEOUT_MS = 60000; // 60s


function toNetworkError(path, e){
  const msg = (e && e.message) ? String(e.message) : String(e||"");
  // Browsers often throw a TypeError with message "Failed to fetch" for CORS / blocked / offline.
  if(String(msg).toLowerCase().includes("failed to fetch") || String(msg).toLowerCase().includes("network")){
    return new Error(
      path + " failed: network error (Failed to fetch). " +
      "This is usually caused by CORS (API must handle OPTIONS + Access-Control-Allow-Origin), " +
      "a blocker/Private DNS blocking workers.dev, or a flaky connection."
    );
  }
  return new Error(path + " failed: " + msg);
}

async function fetchWithTimeout(url, options, timeoutMs){
  const ms = Number(timeoutMs) || FETCH_TIMEOUT_MS;

  // Older browsers: no AbortController support
  if(typeof AbortController === "undefined"){
    return await fetch(url, options||{});
  }

  const ctrl = new AbortController();
  const t = setTimeout(()=>{ try{ ctrl.abort("timeout"); }catch{} }, ms);
  try{
    return await fetch(url, { ...(options||{}), signal: ctrl.signal });
  } finally {
    clearTimeout(t);
  }
}

function toErrorMessage(path, res, json, text){
  const detail = (json && (json.error || json.details || json.message))
    ? (json.error || json.details || json.message)
    : "";
  const body = String(detail || text || "").trim();
  const clipped = body ? body.slice(0, 300) : "";
  return path + " failed: " + res.status + (clipped ? (" — " + clipped) : "");
}

async function apiGet(path){
  let res;
  try{
    res=await fetchWithTimeout(API_BASE+path,{
      method:"GET",
      headers:{Authorization:"Bearer "+session.access_token},
      cache:"no-store"
    }, (path==="/me/cv/ocr/status" ? OCR_STATUS_TIMEOUT_MS : FETCH_TIMEOUT_MS));
  }catch(e){
    throw toNetworkError(path, e);
  }
  const text=await res.text().catch(()=> "");
  let json=null;
  try{json=JSON.parse(text);}catch{json={raw:text};}
  if(!res.ok) throw new Error(toErrorMessage(path, res, json, text));
  return json;
}

async function apiPostJson(path,body){
  let res;
  try{
    res=await fetchWithTimeout(API_BASE+path,{
      method:"POST",
      headers:{Authorization:"Bearer "+session.access_token,"content-type":"application/json"},
      body:JSON.stringify(body||{})
    });
  }catch(e){
    throw toNetworkError(path, e);
  }
  const text=await res.text().catch(()=> "");
  let json=null;
  try{json=JSON.parse(text);}catch{json={raw:text};}
  if(!res.ok) throw new Error(toErrorMessage(path, res, json, text));
  return json;
}

async function saveAiTitlesToBackend(titles){
  try{
    const clean = Array.isArray(titles)
      ? titles.map(t=>String(t||"").trim()).filter(Boolean).slice(0, 30)
      : [];
    if(!clean.length) return { ok:false, saved:0 };

    // Persist AI titles so Dashboard can reliably use "AI titles only"
    const resp = await apiPostJson("/me/ai-titles/save", { ai_titles: clean });
    return resp || { ok:true, saved: clean.length };
  }catch(e){
    // Non-blocking: AI suggestions should still show even if persistence fails
    return { ok:false, error: e && e.message ? e.message : String(e) };
  }
}


async function apiPostForm(path,formData){
  let res;
  try{
    res=await fetchWithTimeout(API_BASE+path,{
      method:"POST",
      headers:{Authorization:"Bearer "+session.access_token},
      body:formData
    }, (path==="/me/cv" ? UPLOAD_TIMEOUT_MS : FETCH_TIMEOUT_MS));
  }catch(e){
    throw toNetworkError(path, e);
  }
  const text=await res.text().catch(()=> "");
  let json=null;
  try{json=JSON.parse(text);}catch{json={raw:text};}
  if(!res.ok) throw new Error(toErrorMessage(path, res, json, text));
  return json;
}

async function ensureCustomer(email){
const res=await fetch(API_BASE+"/customers/upsert",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({email})});
const text=await res.text().catch(()=> "");
if(!res.ok) throw new Error("customers/upsert failed: "+res.status+" "+text);
const data=JSON.parse(text);
if(data && data.customer_id) lsSetAll(LS.customerId, data.customer_id);
return data;
}

function parseCsv(s,limit){
return String(s||"").split(",").map(x=>x.trim()).filter(Boolean).slice(0,limit||30);
}


function lsSafeGet(k){
  try{ return localStorage.getItem(k); }catch(_){ return null; }
}
function lsSafeSet(k, v){
  try{ localStorage.setItem(k, String(v)); }catch(_){}
}

function ssSafeGet(k){
  try{ return sessionStorage.getItem(k); }catch(_){ return null; }
}

function ssSafeSet(k, v){
  try{ sessionStorage.setItem(k, String(v)); }catch(_){}
}

function ssSafeRemove(k){
  try{ sessionStorage.removeItem(k); }catch(_){}
}

function toast(kind, title, message){
  try{
    if(S && typeof S.toast === "function"){
      S.toast(String(message || ""), { kind: kind || "good", title: title || "" });
    }
  }catch(_){}
}

function readJsonStorage(key){
  try{
    const raw = lsSafeGet(key);
    if(!raw) return null;
    const parsed = JSON.parse(raw);
    return parsed && typeof parsed === "object" ? parsed : null;
  }catch(_){
    return null;
  }
}

function writeJsonStorage(key, value){
  try{ lsSafeSet(key, JSON.stringify(value || {})); }catch(_){}
}

function clearGmailVerifyPending(){
  ssSafeRemove(GMAIL_VERIFY_PENDING_KEY);
}

function hasGmailVerifyMarker(){
  try{
    const url = new URL(window.location.href);
    return url.searchParams.get("gmail_verify") === "1";
  }catch(_){
    return false;
  }
}

function clearGmailVerifyMarker(){
  try{
    const url = new URL(window.location.href);
    if(url.searchParams.get("gmail_verify") !== "1") return;
    url.searchParams.delete("gmail_verify");
    const next = url.pathname + (url.search ? url.search : "") + (url.hash ? url.hash : "");
    window.history.replaceState({}, document.title, next);
  }catch(_){}
}

function buildGmailVerifyRedirectUrl(){
  const url = new URL(window.location.href);
  url.searchParams.set("gmail_verify", "1");
  return url.toString();
}

function rememberGoogleProviderTokens(){
  try{
    const auth = getAppAuth();
    if(auth?.cacheGoogleProviderTokens && session){
      auth.cacheGoogleProviderTokens(session);
    }
  }catch(_){}
}

function getCachedGoogleProviderToken(){
  try{
    if(session && typeof session.provider_token === "string" && session.provider_token.trim()){
      return session.provider_token.trim();
    }
  }catch(_){}
  try{
    const auth = getAppAuth();
    if(auth?.getCachedGoogleProviderToken){
      const token = String(auth.getCachedGoogleProviderToken() || "").trim();
      if(token) return token;
    }
  }catch(_){}
  return String(ssSafeGet("jm_google_provider_token") || "").trim();
}

function getGmailVerifyProofForCurrentUser(){
  const proof = readJsonStorage(GMAIL_VERIFY_RESULT_KEY);
  const email = String(session?.user?.email || "").trim().toLowerCase();
  if(!proof || !email) return null;
  if(String(proof.email || "").trim().toLowerCase() !== email) return null;
  return proof;
}

function setGmailVerifyUi(mode, info){
  const badge = $("gmailStatusBadge");
  const hint = $("gmailHint");
  const metaEl = $("gmailMeta");
  const verifyBtn = $("gmailVerifyBtn");
  const sendAgainBtn = $("gmailSendAgainBtn");
  if(!badge || !hint || !metaEl || !verifyBtn || !sendAgainBtn) return;

  const details = info && typeof info === "object" ? info : {};
  const badgeKind = details.badgeKind || "";
  const badgeText = details.badgeText || "Not checked";
  const hintText = details.hint || "Connect Gmail and send a test email to yourself.";
  const metaText = details.meta || "";

  setBadge("gmailStatusBadge", badgeKind, badgeText);
  hint.textContent = hintText;
  metaEl.textContent = metaText;
  metaEl.style.display = metaText ? "block" : "none";

  verifyBtn.disabled = !!details.verifyDisabled;
  verifyBtn.textContent = details.verifyLabel || "Connect Gmail & send test";

  sendAgainBtn.style.display = details.showSendAgain ? "inline-flex" : "none";
  sendAgainBtn.disabled = !!details.sendAgainDisabled;

  if(mode === "checking"){
    verifyBtn.className = "btn";
  } else {
    verifyBtn.className = "btn primary";
  }
}

function refreshGmailVerifyUi(){
  if(!ENABLE_GMAIL){
    const box = $("gmailVerifyBox");
    if(box) box.style.display = "none";
    return;
  }
  const proof = getGmailVerifyProofForCurrentUser();
  const token = getCachedGoogleProviderToken();

  if(gmailVerifyInFlight){
    setGmailVerifyUi("checking", {
      badgeKind: "warn",
      badgeText: "Checking…",
      hint: "Sending a Gmail test message now. Please keep this tab open.",
      verifyLabel: "Working…",
      verifyDisabled: true,
      showSendAgain: false
    });
    return;
  }

  if(proof){
    const when = fmtWhen(proof.sent_at);
    const msgId = String(proof.message_id || "—");
    setGmailVerifyUi("verified", {
      badgeKind: "good",
      badgeText: "Verified",
      hint: "A test email was sent successfully. Check your inbox and Gmail Sent folder to confirm delivery.",
      meta: "Sent to " + String(proof.email || "—") + " at " + when + " · message " + msgId,
      verifyLabel: "Reconnect Gmail",
      showSendAgain: true,
      sendAgainDisabled: !token
    });
    return;
  }

  if(token){
    setGmailVerifyUi("ready", {
      badgeKind: "warn",
      badgeText: "Ready",
      hint: "Google access is available for this tab. Send a test email to confirm Gmail delivery.",
      verifyLabel: "Send Gmail test",
      showSendAgain: false
    });
    return;
  }

  setGmailVerifyUi("idle", {
    badgeKind: "warn",
    badgeText: "Not checked",
    hint: "Connect Gmail and send a test email to yourself. This confirms Gmail delivery end-to-end before you rely on it.",
    verifyLabel: "Connect Gmail & send test",
    showSendAgain: false
  });
}

function buildGmailMimeMessage(toEmail){
  const sentAt = new Date();
  const stamp = sentAt.toLocaleString();
  return [
    "To: " + toEmail,
    "Subject: jobmejob Gmail sending check",
    "Content-Type: text/plain; charset=UTF-8",
    "MIME-Version: 1.0",
    "",
    "This is a Gmail sending test from jobmejob.",
    "Time: " + stamp,
    "",
    "If this email reached your inbox and appears in Gmail Sent, your Gmail send path is working end-to-end."
  ].join("\r\n");
}

function base64UrlEncodeUtf8(text){
  const bytes = new TextEncoder().encode(String(text || ""));
  let binary = "";
  const chunkSize = 0x8000;
  for(let i = 0; i < bytes.length; i += chunkSize){
    const chunk = bytes.subarray(i, i + chunkSize);
    binary += String.fromCharCode.apply(null, Array.from(chunk));
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function gmailErrorMessage(res, payload, text){
  const googleMessage =
    (payload && payload.error && payload.error.message)
      ? String(payload.error.message)
      : String(text || "").trim();

  if(res.status === 401){
    return "Google access expired. Reconnect Gmail and try again.";
  }
  if(res.status === 403){
    return "Google denied Gmail send access. Reconnect Gmail and approve the Gmail permission.";
  }
  return googleMessage || ("HTTP " + res.status);
}

async function sendGmailTestEmail(providerToken, recipientEmail){
  const raw = base64UrlEncodeUtf8(buildGmailMimeMessage(recipientEmail));
  let res;
  try{
    res = await fetchWithTimeout("https://gmail.googleapis.com/gmail/v1/users/me/messages/send", {
      method: "POST",
      headers: {
        Authorization: "Bearer " + providerToken,
        "content-type": "application/json"
      },
      body: JSON.stringify({ raw })
    }, 45000);
  }catch(e){
    throw new Error("Gmail send failed: network error. Please retry.");
  }

  const text = await res.text().catch(()=> "");
  let payload = null;
  try{ payload = JSON.parse(text); }catch(_){ payload = null; }

  if(!res.ok){
    throw new Error("Gmail send failed: " + gmailErrorMessage(res, payload, text));
  }

  return payload && typeof payload === "object" ? payload : {};
}

async function runGmailVerification(){
  const email = String(session?.user?.email || "").trim().toLowerCase();
  const token = getCachedGoogleProviderToken();
  if(!email) throw new Error("Signed-in email is missing.");
  if(!token) throw new Error("Google access token is missing. Reconnect Gmail and try again.");

  gmailVerifyInFlight = true;
  refreshGmailVerifyUi();

  try{
    const result = await sendGmailTestEmail(token, email);
    writeJsonStorage(GMAIL_VERIFY_RESULT_KEY, {
      email,
      sent_at: new Date().toISOString(),
      message_id: result.id || null,
      thread_id: result.threadId || null,
      provider: "google",
      via: "gmail_api_browser"
    });
    clearGmailVerifyPending();
    clearGmailVerifyMarker();
    refreshGmailVerifyUi();
    toast("good", "Gmail verified", "Test email sent to " + email + ".");
    return result;
  } catch (e){
    clearGmailVerifyPending();
    clearGmailVerifyMarker();
    try{ localStorage.removeItem(GMAIL_VERIFY_RESULT_KEY); }catch(_){}
    refreshGmailVerifyUi();
    throw e;
  } finally {
    gmailVerifyInFlight = false;
    refreshGmailVerifyUi();
  }
}

async function startGmailOAuthFlow(){
  const auth = getAppAuth();
  if(!auth || typeof auth.loginWithGoogle !== "function"){
    throw new Error("Google auth helper is unavailable.");
  }
  try{
    auth.rememberPostAuthRedirect?.(buildGmailVerifyRedirectUrl());
  }catch(_){}

  ssSafeSet(GMAIL_VERIFY_PENDING_KEY, "1");
  setGmailVerifyUi("checking", {
    badgeKind: "warn",
    badgeText: "Redirecting…",
    hint: "Redirecting to Google so you can approve Gmail send access.",
    verifyLabel: "Redirecting…",
    verifyDisabled: true
  });

  await auth.loginWithGoogle({
    redirectTo: window.location.origin + "/",
    scopes: GMAIL_VERIFY_SCOPE,
    queryParams: {
      prompt: "consent",
      include_granted_scopes: "true"
    }
  });
}

async function handleGmailVerifyClick(){
  clearTopError();
  const proof = getGmailVerifyProofForCurrentUser();
  if(proof){
    await startGmailOAuthFlow();
    return;
  }

  if(getCachedGoogleProviderToken()){
    await runGmailVerification();
    return;
  }

  await startGmailOAuthFlow();
}

async function handleGmailSendAgainClick(){
  clearTopError();
  if(getCachedGoogleProviderToken()){
    await runGmailVerification();
    return;
  }
  await startGmailOAuthFlow();
}

async function maybeFinishPendingGmailVerify(){
  if(!ENABLE_GMAIL) return;
  rememberGoogleProviderTokens();
  if(!hasGmailVerifyMarker() && ssSafeGet(GMAIL_VERIFY_PENDING_KEY) !== "1"){
    refreshGmailVerifyUi();
    return;
  }

  if(!getCachedGoogleProviderToken()){
    clearGmailVerifyPending();
    clearGmailVerifyMarker();
    setGmailVerifyUi("failed", {
      badgeKind: "bad",
      badgeText: "Token missing",
      hint: "Google returned without a Gmail access token. Reconnect Gmail and approve the Gmail permission.",
      verifyLabel: "Reconnect Gmail",
      showSendAgain: false
    });
    return;
  }

  try{
    await runGmailVerification();
  }catch(e){
    showTopError(e?.message || String(e));
  }
}

function maybeAutofillJobTitlesFromAi(titles){
  try{
    if(jobTitlesTouched) return false;
    const el = $("jobTitles");
    if(!el) return false;

    const current = parseCsv(el.value, 30);
    if(current.length) return false;

    const clean = Array.isArray(titles) ? titles.map(t=>String(t||"").trim()).filter(Boolean) : [];
    const pick = clean.slice(0, 6);
    if(!pick.length) return false;

    el.value = pick.join(", ");

    aiAppliedOnce = true;
    aiAppliedTitles = pick.slice(0, 12);
    renderAiAppliedChips(aiAppliedTitles);

    markPrefsDirty();
scheduleAutoSave();
    return true;
  }catch(_){
    return false;
  }
}


function setJobsPrefetchUI(state, info){
  if(!ENABLE_JOB_MATCHING) return;
  const badge=$("jobsPrefetchBadge");
  const row=$("jobsPrefetchRow");
  const textEl=$("jobsPrefetchText");
  if(!badge || !row || !textEl) return;

  const s=String(state||"").toLowerCase();

  if(s==="running"){
    badge.style.display="inline-flex";
    badge.className="badge warn";
    badge.textContent="Fetching jobs…";
    row.style.display="flex";
    textEl.textContent = (info && info.text) ? String(info.text) : "Fetching matched jobs in the background…";
    return;
  }

  if(s==="ready"){
    const n = info && Number.isFinite(info.count) ? Number(info.count) : null;
    if(n !== null && n > 0){
      badge.style.display="inline-flex";
      badge.className="badge good";
      badge.textContent = n + " jobs ready";
    }else{
      // No new jobs added → don't clutter UI
      badge.style.display="none";
    }
    row.style.display="none";
    return;
  }

  if(s==="pending"){
    badge.style.display="inline-flex";
    badge.className="badge warn";
    badge.textContent="Jobs pending";
    row.style.display="none";
    return;
  }

  // idle
  badge.style.display="none";
  row.style.display="none";
}

function renderClickChips(hostId, items, onClick){
  const host=$(hostId);
  if(!host) return;
  host.innerHTML="";
  const clean = Array.isArray(items) ? items.map(x=>String(x||"").trim()).filter(Boolean) : [];
  if(!clean.length) return;

  const wrap=document.createElement("div");
  wrap.className="chips";
  clean.forEach((label, idx)=>{
    const chip=document.createElement("div");
    chip.className="chip quick";
    chip.style.animationDelay = (idx * 35) + "ms";
    chip.textContent=label;
    chip.addEventListener("click", ()=>{
      try{ onClick && onClick(label); }catch(_){}
    });
    wrap.appendChild(chip);
  });
  host.appendChild(wrap);
}

const CITY_ALIASES = [
  { name:"Berlin", aliases:["berlin"] },
  { name:"Hamburg", aliases:["hamburg"] },
  { name:"München", aliases:["münchen","munchen","munich"] },
  { name:"Köln", aliases:["köln","koeln","cologne"] },
  { name:"Frankfurt", aliases:["frankfurt","frankfurt am main"] },
  { name:"Stuttgart", aliases:["stuttgart"] },
  { name:"Düsseldorf", aliases:["düsseldorf","dusseldorf"] },
  { name:"Leipzig", aliases:["leipzig"] },
  { name:"Dresden", aliases:["dresden"] },
  { name:"Nürnberg", aliases:["nürnberg","nurnberg","nuernberg","nuremberg"] },
  { name:"Hannover", aliases:["hannover"] },
  { name:"Bremen", aliases:["bremen"] },
  { name:"Dortmund", aliases:["dortmund"] },
  { name:"Essen", aliases:["essen"] },
  { name:"Bonn", aliases:["bonn"] },
  { name:"Mannheim", aliases:["mannheim"] },
  { name:"Karlsruhe", aliases:["karlsruhe"] },
  { name:"Freiburg", aliases:["freiburg"] },
  { name:"Heidelberg", aliases:["heidelberg"] }
];

function normalizeLocationString(s){
  let v = String(s||"").trim();
  if(!v) return "";
  v = v.replace(/\s+/g," ");
  v = v.split("|")[0].trim();
  v = v.split("·")[0].trim();
  // Remove trailing country tokens
  v = v.replace(/,\s*(germany|deutschland|de)\s*$/i, "");
  // Keep first segment (city)
  const first = v.split(",")[0].trim();
  return first;
}

function findCitiesInText(s){
  const t = String(s||"").toLowerCase();
  const out = [];
  for(const c of CITY_ALIASES){
    if(out.includes(c.name)) continue;
    for(const a of c.aliases){
      if(t.includes(a)){
        out.push(c.name);
        break;
      }
    }
  }
  return out;
}

function deriveLocationHintsFromAiResult(r){
  const out = [];

  try{
    const rawCandidates = [];

    // Common keys (best-effort, backend may change)
    if(r){
      if(Array.isArray(r.locations)) rawCandidates.push(...r.locations);
      if(typeof r.location === "string") rawCandidates.push(r.location);
      if(typeof r.city === "string") rawCandidates.push(r.city);
      if(typeof r.current_location === "string") rawCandidates.push(r.current_location);
      if(typeof r.base_location === "string") rawCandidates.push(r.base_location);

      if(r.contact){
        if(typeof r.contact.location === "string") rawCandidates.push(r.contact.location);
        if(typeof r.contact.city === "string") rawCandidates.push(r.contact.city);
      }
      if(r.profile){
        if(typeof r.profile.location === "string") rawCandidates.push(r.profile.location);
        if(typeof r.profile.city === "string") rawCandidates.push(r.profile.city);
      }

      if(typeof r.summary === "string") rawCandidates.push(r.summary);
    }

    // Normalize location-like strings and scan for cities
    for(const cand of rawCandidates){
      const norm = normalizeLocationString(cand);
      const cities = findCitiesInText(norm);
      if(cities.length){
        out.push(...cities);
        continue;
      }

      // If norm looks like a city (single word, capitalized), use it cautiously
      if(norm && norm.length <= 32 && /^[A-Za-zÀ-ž\-\s]+$/.test(norm)){
        out.push(norm);
      }
    }

    // De-dup, keep first 3
    const uniq = [];
    for(const x of out){
      const v = String(x||"").trim();
      if(!v) continue;
      if(uniq.map(z=>z.toLowerCase()).includes(v.toLowerCase())) continue;
      uniq.push(v);
      if(uniq.length >= 3) break;
    }
    return uniq;
  }catch(_){
    return [];
  }
}

function setLocationSuggestionUI(list){
  const wrap=$("locSuggestWrap");
  const btn=$("useCvLocationBtn");
  if(!wrap) return;

  const cities = Array.isArray(list) ? list.map(x=>String(x||"").trim()).filter(Boolean) : [];
  cvLocationHint = cities.slice(0,3);

  if(!cities.length){
    wrap.style.display="none";
    if(btn) btn.style.display="none";
    return;
  }

  wrap.style.display="block";
  renderClickChips("locSuggestChips", cities, (label)=>{
    applyLocation(label, { source:"cv", append:false });
  });

  if(btn){
    btn.style.display="inline-flex";
    btn.onclick = (e)=>{
      e.preventDefault();
      applyLocation(cities[0], { source:"cv", append:false });
    };
  }
}

function applyLocation(label, opts){
  opts = opts || {};
  const el=$("locations");
  if(!el) return;

  const val = String(label||"").trim();
  if(!val) return;

  const current = parseCsv(el.value, 20);

  let next = [];
  if(opts.append){
    next = [...new Set([...current, val])].slice(0, 20);
  }else{
    next = [val, ...current.filter(x=>x.toLowerCase() !== val.toLowerCase())].slice(0, 20);
  }

  el.value = next.join(", ");
  locationsTouched = true;

  try{ if(opts && opts.source === "cv"){ const b=$("useCvLocationBtn"); if(b) b.style.display = "none"; } }catch(_){ }

  markPrefsDirty();
scheduleAutoSave();
}

async function maybePrefetchJobs(aiTitles, reason){
  if(!ENABLE_JOB_MATCHING) return { ok:false, skipped:true };
  const titles = Array.isArray(aiTitles) ? aiTitles.map(t=>String(t||"").trim()).filter(Boolean) : [];
  if(!titles.length) return;

  if(jobsPrefetchInFlight) return;
  jobsPrefetchInFlight = true;

  try{
    // Rate limit (avoid spamming the worker)
    const now = Date.now();
    const last = Number(lsSafeGet("jm_jobs_prefetch_ts") || "0");
    const minMs = 6 * 60 * 60 * 1000; // 6h
    if(last && (now - last) < minMs) return;

    if(!session || !session.access_token) return;

    setJobsPrefetchUI("running", { text: "Fetching matched jobs based on your CV… (background)" });

    const fetch_mode = (state && state.profile_complete) ? "profile" : "ai_only";

    const resp = await apiPostJson("/me/jobs/fetch", {
      include_ai_titles: true,
      ai_titles: titles.slice(0, 12),
      fetch_mode,
      reason: String(reason || "profile_autofetch")
    });

    // Only set the rate-limit timestamp when the request actually happened
    lsSafeSet("jm_jobs_prefetch_ts", String(now));

    const added = (resp && typeof resp.jobs_added === "number") ? resp.jobs_added : 0;

    setJobsPrefetchUI("ready", { count: Number(added) });

    if(added > 0){
      toast("good", "Jobs ready", "Fetched " + added + " matched jobs in the background.");
    }
  }catch(_){
    // keep UI calm (do not scare the user)
    setJobsPrefetchUI("pending");
  }finally{
    jobsPrefetchInFlight = false;
  }
}


function wireCvDropzone(){
  const dz = $("cvDropzone");
  const input = $("cvFile");
  const browse = $("browseCvBtn");

  if(browse && input){
    browse.addEventListener("click", (e)=>{
      e.preventDefault();
      try{ input.click(); }catch(_){}
    });
  }

  if(!dz) return;

  const openPicker = (e)=>{
    try{
      if(e && e.target && e.target.closest && e.target.closest("button")) return;
    }catch(_){}
    if(input){ try{ input.click(); }catch(_){ } }
  };

  dz.addEventListener("click", openPicker);
  dz.addEventListener("keydown", (e)=>{
    if(e.key === "Enter" || e.key === " "){
      e.preventDefault();
      openPicker(e);
    }
  });

  dz.addEventListener("dragover", (e)=>{
    e.preventDefault();
    dz.classList.add("dragOver");
  });
  dz.addEventListener("dragleave", ()=>{
    dz.classList.remove("dragOver");
  });
  dz.addEventListener("drop", async (e)=>{
    e.preventDefault();
    dz.classList.remove("dragOver");
    const file = e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0] ? e.dataTransfer.files[0] : null;
    if(!file) return;

    try{
      jobTitlesTouched=false;
      aiAppliedTitles=[];
      renderAiAppliedChips(aiAppliedTitles);
      await uploadCvThenAutoOcr(file);
    }catch(err){
      setBadge("cvStatusBadge","bad","Upload failed");
      setProgress(false, 0, "", "");
      showTopError(err?.message || String(err));
    }
  });
}

async function maybeAutoGenerateAiTitles(reason){
  try{
    if(aiAutoStarted) return;
    if(!lastCvMeta) return;

    // If suggestions already exist in UI, just prefetch jobs and stop.
    if(aiGeneratedOnce && aiResult && Array.isArray(aiResult.titles) && aiResult.titles.length){
      aiAutoStarted = true;
      try{ await maybePrefetchJobs(aiResult.titles, reason || "already"); }catch(_){ }
      return;
    }

    // Try cache first (fast)
    if(tryLoadCachedAiSuggestions()){
      aiAutoStarted = true;
      const t = (aiResult && Array.isArray(aiResult.titles)) ? aiResult.titles : [];
      if(t.length) await maybePrefetchJobs(t, reason || "cache");
      return;
    }

    // Cooldown per CV (avoid regenerating on every refresh)
    const key = cvMetaKey(lastCvMeta);
    const lastKey = lsSafeGet("jm_ai_autogen_cvkey") || "";
    const lastAt = Number(lsSafeGet("jm_ai_autogen_at") || "0");
    const minMs = 24 * 60 * 60 * 1000; // 24h

    if(lastKey === key && lastAt && (Date.now() - lastAt) < minMs){
      // Already tried recently; allow manual button.
      return;
    }

    lsSafeSet("jm_ai_autogen_cvkey", key);
    lsSafeSet("jm_ai_autogen_at", String(Date.now()));

    aiAutoStarted = true;

    setBadge("aiStatusBadge","warn","Auto…");
    setText("aiHint","Generating suggestions automatically…");

    const titles = await handleAiGenerate({ force:false, background:true });
    const t = Array.isArray(titles) ? titles : ((aiResult && Array.isArray(aiResult.titles)) ? aiResult.titles : []);

    if(t.length){
      await maybePrefetchJobs(t, reason || "autogen");
    }else{
      // allow manual retry
      aiAutoStarted = false;
      setBadge("aiStatusBadge","warn","Manual");
      setText("aiHint","Automatic generation didn’t work this time. Click “Generate now” to try again.");
    }
  }catch(_){
    aiAutoStarted = false;
  }
}


function isPdfFile(file){
const name=String(file?.name||"").toLowerCase();
const type=String(file?.type||"").toLowerCase();
return name.endsWith(".pdf") || type==="application/pdf";
}

function setProgress(show, pct, text, hint){
$("cvProgressWrap").style.display = show ? "block" : "none";
$("cvProgressFill").style.width = Math.max(0, Math.min(100, Number(pct)||0)) + "%";
setText("cvProgressText", text || "");
setText("cvProgressHint", hint || "");
}

function stopOcrPolling(){
if(ocrPollTimer){clearInterval(ocrPollTimer);ocrPollTimer=null;}
}

// OCR polling configuration
const OCR_FAST_POLL_MS = 3500;
const OCR_SLOW_POLL_MS = 15000;
const OCR_SOFT_WAIT_MS = 3 * 60 * 1000;   // after this: show retry + slow polling
const OCR_HARD_WAIT_MS = 15 * 60 * 1000;  // after this: stop auto polling (user can retry manually)

let ocrPollInFlight=false;
let ocrPollTicks=0;

function showRetryOcr(show){
  const b=$("retryOcrBtn");
  if(!b) return;
  b.style.display = show ? "inline-flex" : "none";
}

function unlockAiWhileOcrRunning(){
  setBadge("aiStatusBadge","warn","OCR running…");
  $("aiGenerateBtn").disabled=false;
  $("aiApplyBtn").disabled=true;
  $("aiRegenerateLink").style.display="none";
  setText("aiHint","OCR is still running. We’ll auto-generate titles once it’s done (you can also try now).");
}

function unlockAiFallback(msg){
  setBadge("aiStatusBadge","warn","Try anyway");
  $("aiGenerateBtn").disabled=false;
  $("aiApplyBtn").disabled=true;
  $("aiRegenerateLink").style.display="none";
  setText("aiHint", msg || "You can try generating suggestions now. If it fails, upload a PDF or retry OCR.");
}

function stopOcrPollingAndCleanup(){
  stopOcrPolling();
  ocrPollInFlight=false;
  ocrPollTicks=0;
}

function startOcrPolling(opts){
  opts = opts || {};
  const startedAt = (typeof opts.startedAt === "number" && Number.isFinite(opts.startedAt)) ? opts.startedAt : Date.now();
  let pollMs = OCR_FAST_POLL_MS;
  let slowMode = false;

  stopOcrPollingAndCleanup();

  async function tick(){
    if(ocrPollInFlight) return;
    ocrPollInFlight=true;
    ocrPollTicks++;

    const elapsed = Date.now() - startedAt;
    const pct = Math.min(95, 55 + Math.floor((elapsed / OCR_HARD_WAIT_MS) * 40));

    try{
      // Refresh onboarding status occasionally (avoid spamming)
      if(ocrPollTicks % 4 === 1){
        try{ await refreshState(); }catch(_){}
      }

      // Important: /me/cv/ocr/status "finalizes" OCR by fetching Vision output from GCS and storing text in DB.
      // Without calling it, cv_ocr_status can stay stuck on "processing" forever.
      if(ocrPollTicks % 2 === 1){
        try{ await apiGet("/me/cv/ocr/status"); }catch(_){ /* ignore transient errors; we will retry */ }
      }

      const res = await apiGet("/me/cv");
      const cv = res && res.cv ? res.cv : null;
      const s = String(cv?.cv_ocr_status||"").toLowerCase();

      if(s==="done"){
        stopOcrPollingAndCleanup();
        showRetryOcr(false);
        setProgress(false, 100, "", "");
        setBadge("cvStatusBadge","good","OCR done");
        setText("ocrHint","OCR done. You can generate AI suggestions now.");
        lastCvMeta=cvMetaFromCv(cv);
        unlockAiReady();
        tryLoadCachedAiSuggestions();
        maybeAutoGenerateAiTitles("ocr_done");
        return;
      }

      if(s==="failed"){
        stopOcrPollingAndCleanup();
        showRetryOcr(true);
        setProgress(false, 0, "", "");
        setBadge("cvStatusBadge","bad","OCR failed");
        setText("ocrHint","OCR failed: "+(cv?.cv_ocr_error||""));
        unlockAiFallback("OCR failed. You can retry OCR or try generating suggestions anyway.");
        return;
      }

      // processing / idle / unknown
      if(elapsed > OCR_SOFT_WAIT_MS){
        showRetryOcr(true);
        setText("ocrHint","OCR is taking longer than usual… You can keep this page open or tap Retry OCR.");
      }else{
        showRetryOcr(false);
        setText("ocrHint","OCR is running…");
      }

      setBadge("cvStatusBadge","warn","OCR running…");
      setProgress(true, pct, "OCR in progress…", "We will update automatically.");

      // Allow trying AI even while OCR runs
      unlockAiWhileOcrRunning();

      if(!slowMode && elapsed > OCR_SOFT_WAIT_MS){
        slowMode = true;
        // switch to slower polling
        if(ocrPollTimer){ clearInterval(ocrPollTimer); }
        ocrPollTimer = setInterval(tick, OCR_SLOW_POLL_MS);
      }

      if(elapsed > OCR_HARD_WAIT_MS){
        stopOcrPollingAndCleanup();
        showRetryOcr(true);
        setBadge("cvStatusBadge","warn","OCR delayed");
        setProgress(false, 0, "", "");
        setText("ocrHint","OCR is still processing. Tap Retry OCR or refresh later.");
        unlockAiFallback("OCR is delayed. You can try generating suggestions anyway, or tap Retry OCR.");
      }

    }catch(e){
      // Network/CORS flakiness: keep trying; do not hard-fail the UI.
      setBadge("cvStatusBadge","warn","Checking…");
      setProgress(true, pct, "Checking OCR status…", "If you are on mobile, this can fail due to network/CORS. We'll keep trying.");
      // Avoid spamming the top error box every tick.
      if(ocrPollTicks === 1 || (ocrPollTicks % 8 === 0)){
        showTopError(e.message||String(e));
      }
      if(elapsed > OCR_SOFT_WAIT_MS) showRetryOcr(true);
      unlockAiWhileOcrRunning();
    }finally{
      ocrPollInFlight=false;
    }
  }

  tick();
  ocrPollTimer = setInterval(tick, pollMs);
}


function markStep1DoneVisual(isDone){
const card=$("step1Card");
if(!card) return;
card.classList.toggle("stepDone", !!isDone);
}

function lockAi(msg){
setBadge("aiStatusBadge","warn","Locked");
$("aiGenerateBtn").disabled=true;
$("aiApplyBtn").disabled=true;
$("aiRegenerateLink").style.display="none";
aiResult=null;
aiSelectedTitles=new Set();
$("aiTitlesWrap").style.display="none";
setText("aiHint", msg || "Upload your CV first. When OCR is done, you can generate suggestions.");
aiGeneratedOnce=false;
aiAppliedOnce=false;
}

function unlockAiReady(){
setBadge("aiStatusBadge","good","Ready");
$("aiGenerateBtn").disabled=false;
$("aiApplyBtn").disabled=true;
$("aiRegenerateLink").style.display="none";
setText("aiHint","Your CV text is ready. We’ll generate job title suggestions automatically (and save them to your account).");
aiGeneratedOnce=false;
aiAppliedOnce=false;
}

function renderChips(containerId, items, selectedSet){
const wrap=$(containerId);
wrap.style.display="block";
wrap.innerHTML="";
const chips=document.createElement("div");
chips.className="chips";
items.forEach((t, idx)=>{
const chip=document.createElement("div");
chip.className="chip"+(selectedSet && selectedSet.has(t) ? " selected" : "");
chip.style.animationDelay = (idx * 45) + "ms";
chip.textContent=t;
chip.addEventListener("click",()=>{
if(!selectedSet) return;
if(selectedSet.has(t)) selectedSet.delete(t); else selectedSet.add(t);
renderChips(containerId, items, selectedSet);
$("aiApplyBtn").disabled = selectedSet.size===0;
});
chips.appendChild(chip);
});
wrap.appendChild(chips);
}

function renderAiAppliedChips(titles){
const wrap=$("aiAppliedWrap");
const chipsHost=$("aiAppliedChips");
if(!wrap || !chipsHost) return;
if(!titles || !titles.length || jobTitlesTouched){
wrap.style.display="none";
chipsHost.innerHTML="";
return;
}
wrap.style.display="block";
chipsHost.innerHTML="";
const chips=document.createElement("div");
chips.className="chips";
titles.forEach((t, idx)=>{
const chip=document.createElement("div");
chip.className="chip aiTag";
chip.style.animationDelay = (idx * 35) + "ms";
chip.textContent=t;
chips.appendChild(chip);
});
chipsHost.appendChild(chips);
}

function setOnboardingUI(st){
const signed=!!(session && session.user && session.user.email);
setBadge("signedInBadge",signed?"good":"warn",signed?"Signed in":"Not signed in");
setText("kSigned",signed?"Yes":"No");
const customerId=st && st.customer_id ? String(st.customer_id) : (lsGetFirst(LS.customerId)||"");
setText("kCustomerId",customerId||"—");
const profOk=!!(st && st.profile_complete);
setText("kProfile",profOk?"Yes":"No");
$("kProfile").className="kpiVal "+(profOk?"ok":"bad");
const planOk=!!(st && st.plan_id);
setText("kPlan",planOk?"Yes":"No");
$("kPlan").className="kpiVal "+(planOk?"ok":"warn");
const cvOk=!!(st && st.cv_uploaded);
setText("kCv",cvOk?"Yes":"No");
$("kCv").className="kpiVal "+(cvOk?"ok":"warn");
const ocr=String(st && st.cv_ocr_status ? st.cv_ocr_status : "").toLowerCase();
if(ocr==="done"){
setText("kOcr","done");
$("kOcr").className="kpiVal ok";
}else if(ocr==="processing"){
setText("kOcr","processing");
$("kOcr").className="kpiVal warn";
}else if(ocr==="failed"){
setText("kOcr","failed");
$("kOcr").className="kpiVal bad";
}else{
setText("kOcr","idle");
$("kOcr").className="kpiVal warn";
}
// Next action (keep it simple): CV Studio is the core flow.
// If something is missing, we guide the user by scrolling to the right section.
const cvOk2 = !!(st && st.cv_uploaded);
const profOk2 = !!(st && st.profile_complete);

// Keep "Open CV Studio" gated behind CV upload (tailoring needs a base CV).
try{
  const openBtn = $("openCvBtn");
  if(openBtn){
    openBtn.disabled = !cvOk2;
    openBtn.textContent = cvOk2 ? "Open CV Studio" : "Upload CV first";
  }
}catch(_){}

if(!cvOk2){
setText("continueBtn","Upload CV to start");
setText("continueHint","Upload your CV to unlock tailoring. (PDF recommended)");
}else if(!profOk2){
setText("continueBtn","Open CV Studio");
setText("continueHint",STANDALONE_MODE ? "You can tailor your CV now. Open CV Studio and paste a job description." : "You can tailor your CV now. To also get matched jobs, add a location and save preferences below (recommended).");
}else{
setText("continueBtn","Open CV Studio");
setText("continueHint",STANDALONE_MODE ? "You're all set. Open CV Studio and tailor your CV with a pasted job description." : "You're all set. Next: tailor your CV (ATS-safe).");
}
}

async function refreshState(){
state=await apiGet("/me/state");
setOnboardingUI(state);
}

async function loadProfileIntoForm(){
try{
const prof=await apiGet("/me/profile");
const p=prof && prof.profile ? prof.profile : null;
if(!p) return;
const desired=Array.isArray(p.desired_titles)?p.desired_titles:[];
const industries=Array.isArray(p.industries)?p.industries:[];
const locations=Array.isArray(p.locations)?p.locations:[];
const countries=Array.isArray(p.countries_allowed)?p.countries_allowed:[];
const radius=p.radius_km;
$("jobTitles").value=desired.join(", ");
$("industries").value=industries.join(", ");
$("locations").value=locations.join(", ");
locationsTouched = locations.length ? true : false;
try{ if(locations.length){ setLocationSuggestionUI([]); } }catch(_){}

if(countries[0]) $("country").value=String(countries[0]);
if(radius!==null && radius!==undefined) $("radiusKm").value=String(radius);
setBadge("saveStatusBadge","good","Loaded");
}catch{}
}

function getAiCache(){
try{
let raw=localStorage.getItem(AI_CACHE_KEY);
if(!raw) raw=localStorage.getItem(AI_CACHE_KEY_OLD);
if(!raw) return null;
const v=JSON.parse(raw);
if(!v || typeof v !== "object") return null;
return v;
}catch{
return null;
}
}

function setAiCache(payload){
try{
  localStorage.setItem(AI_CACHE_KEY, JSON.stringify(payload));
}catch{}
}

function clearAiCache(){
try{localStorage.removeItem(AI_CACHE_KEY);}catch{}
try{localStorage.removeItem(AI_CACHE_KEY_OLD);}catch{}
}

function cvMetaFromCv(cv){
return {
cv_path: String(cv?.cv_path || ""),
cv_filename: String(cv?.cv_filename || ""),
cv_uploaded_at: String(cv?.cv_uploaded_at || ""),
cv_ocr_status: String(cv?.cv_ocr_status || ""),
cv_ocr_updated_at: String(cv?.cv_ocr_updated_at || ""),
cv_text_status: String(cv?.cv_text_status || "")
};
}

function cvMetaKey(meta){
return [
meta.cv_path,
meta.cv_filename,
meta.cv_uploaded_at,
meta.cv_ocr_status,
meta.cv_ocr_updated_at,
meta.cv_text_status
].join("|");
}

function applyAiUiFromTitles(titles){
  const clean = Array.isArray(titles)
    ? titles.map(x=>String(x).trim()).filter(Boolean).slice(0,30)
    : [];
  if(!clean.length) return false;

  aiResult = { titles: clean };

  // Default selection: top 6 (less overwhelming)
  const defaultPick = clean.slice(0, 6);
  aiSelectedTitles = new Set(defaultPick.length ? defaultPick : clean.slice(0, 3));
  aiGeneratedOnce = true;

  // Persist for other pages (Jobs toggle: "AI titles only")
  try{
    localStorage.setItem("jm_ai_titles_server", JSON.stringify(clean));
  }catch(_){}

  setBadge("aiStatusBadge","good","Ready");
  setText("aiHint","Generated automatically and saved to your account. (Optional) Adjust selection, then update your job titles below.");
  setHtml("aiTitlesWrap","<div class='small'><strong>Suggested titles</strong> (click to select)</div>");
  renderChips("aiTitlesWrap", clean, aiSelectedTitles);

  $("aiApplyBtn").disabled = aiSelectedTitles.size===0;
  $("aiGenerateBtn").disabled = true;
  $("aiRegenerateLink").style.display = "inline";

  // Best practice: prefill job titles if the user hasn't typed anything yet.
  maybeAutofillJobTitlesFromAi(clean);

  return true;
}

function tryLoadCachedAiSuggestions(){
const cache=getAiCache();
if(!cache || !lastCvMeta) return false;
const currentKey=cvMetaKey(lastCvMeta);
if(cache.cvMetaKey !== currentKey) return false;
if(!Array.isArray(cache.titles) || !cache.titles.length) return false;
return applyAiUiFromTitles(cache.titles);
}

async function loadCvStatusAndUpdateUx(){
  try{
    const res=await apiGet("/me/cv");
    const cv=res && res.cv ? res.cv : null;

    if(cv && cv.cv_path){
      lastCvMeta=cvMetaFromCv(cv);

      const fileLabel = cv.cv_filename || cv.cv_path;
      const fileLower = String(fileLabel||"").toLowerCase();
      const isPdf = fileLower.endsWith(".pdf");

      setText("cvHint","Uploaded: "+fileLabel);
      showRetryOcr(false);

      const s=String(cv.cv_ocr_status||"").toLowerCase();

      if(s==="done"){
        stopOcrPollingAndCleanup();
        setBadge("cvStatusBadge","good","OCR done");
        setText("ocrHint","OCR done. You can generate AI suggestions now.");
        setProgress(false, 100, "", "");
        unlockAiReady();
        tryLoadCachedAiSuggestions();
        maybeAutoGenerateAiTitles("ocr_done");
        return;
      }

      if(s==="processing"){
        setBadge("cvStatusBadge","warn","OCR running…");
        setProgress(true, 65, "OCR in progress…", "We will update automatically.");
        setText("ocrHint","OCR is running…");
        if(isPdf){
          unlockAiWhileOcrRunning();
          startOcrPolling({ startedAt: Date.now() });
        }else{
          lockAi("For OCR and AI suggestions, please upload a PDF version.");
        }
        markStep1DoneVisual(false);
        return;
      }

      if(s==="failed"){
        stopOcrPollingAndCleanup();
        setBadge("cvStatusBadge","bad","OCR failed");
        setProgress(false, 0, "", "");
        setText("ocrHint","OCR failed: "+(cv.cv_ocr_error||""));
        if(isPdf){
          showRetryOcr(true);
          unlockAiFallback("OCR failed. Tap Retry OCR or try generating suggestions anyway.");
        }else{
          lockAi("OCR failed. Please upload a PDF.");
        }
        markStep1DoneVisual(false);
        return;
      }

      // idle / unknown
      stopOcrPollingAndCleanup();
      setBadge("cvStatusBadge","good","Uploaded");
      setProgress(false, 0, "", "");
      if(isPdf){
        setText("ocrHint","OCR not started yet. Tap Retry OCR to start.");
        showRetryOcr(true);
        unlockAiFallback("CV uploaded. Tap Retry OCR to extract text, or try generating suggestions anyway.");
      }else{
        setText("ocrHint","Upload a PDF to enable OCR.");
        lockAi("Upload a PDF to enable OCR and AI suggestions.");
      }
      markStep1DoneVisual(false);
      return;
    }

    // No CV on backend
    lastCvMeta=null;
    stopOcrPollingAndCleanup();
    showRetryOcr(false);
    setBadge("cvStatusBadge","warn","No CV");
    setText("cvHint","No CV uploaded yet.");
    setText("ocrHint","");
    setProgress(false, 0, "", "");
    lockAi("Upload your CV first. Then you can generate suggestions.");
    markStep1DoneVisual(false);
  }catch(e){
    lastCvMeta=null;
    stopOcrPollingAndCleanup();
    showRetryOcr(false);
    setBadge("cvStatusBadge","warn","Unknown");
    setText("cvHint","Could not load CV status.");
    setText("ocrHint","");
    setProgress(false, 0, "", "");
    lockAi("Upload your CV first. Then you can generate suggestions.");
    showTopError(e.message||String(e));
    markStep1DoneVisual(false);
  }
}

async function uploadCvThenAutoOcr(file){
  stopOcrPollingAndCleanup();
  clearTopError();
  showRetryOcr(false);
  lockAi("Working on your CV…");
  clearAiCache();

  // New CV = new titles. Reset background pipeline + cached AI titles.
  aiAutoStarted = false;
  backendAiTitles = [];
  try{ localStorage.removeItem("jm_ai_titles_server"); }catch(_){ }
  try{ localStorage.removeItem("ja_ai_titles_server"); }catch(_){ }

  // Basic size guard (many edge runtimes reject large uploads)
  const maxSizeMb = 9;
  if(file && Number(file.size) > maxSizeMb*1024*1024){
    throw new Error("File too large ("+Math.round(file.size/1024/1024)+"MB). Please upload a PDF under "+maxSizeMb+"MB.");
  }

  setBadge("cvStatusBadge","warn","Uploading…");
  setProgress(true, 18, "Uploading your CV…", "Do not close this tab.");

  const fd=new FormData();
  fd.append("cv",file);
  await apiPostForm("/me/cv",fd);

  await refreshState();
  await loadCvStatusAndUpdateUx();

  if(!isPdfFile(file)){
    setProgress(false, 0, "", "");
    setText("ocrHint","For OCR and AI suggestions, please upload a PDF version.");
    lockAi("Upload a PDF to enable OCR and AI suggestions.");
    showRetryOcr(false);
    return;
  }

  setBadge("cvStatusBadge","warn","Starting OCR…");
  setProgress(true, 40, "Starting OCR…", "We are extracting text from your PDF.");

  try{
    await apiPostJson("/me/cv/ocr",{});
  }catch(e){
    // Non-fatal: user can retry OCR manually
    showTopError(e.message||String(e));
    showRetryOcr(true);
  }

  setBadge("cvStatusBadge","warn","OCR running…");
  setProgress(true, 55, "OCR in progress…", "We will update automatically.");
  setText("ocrHint","OCR is running…");
  unlockAiWhileOcrRunning();
  startOcrPolling({ startedAt: Date.now() });
}

async function handleCvFileSelected(){
try{
const input=$("cvFile");
const file=input && input.files && input.files[0] ? input.files[0] : null;
if(!file) return;
// Allow selecting the same file again (common issue on Android/Samsung browsers)
try{ if(input) input.value=""; }catch{}
jobTitlesTouched=false;
aiAppliedTitles=[];
renderAiAppliedChips(aiAppliedTitles);
await uploadCvThenAutoOcr(file);
}catch(e){
setBadge("cvStatusBadge","bad","Upload failed");
setProgress(false, 0, "", "");
showTopError(e.message||String(e));
}
}

async function handleRetryOcr(){
  clearTopError();
  const btn=$("retryOcrBtn");
  if(btn) btn.disabled=true;

  try{
    // Ensure a PDF CV exists on backend
    const res=await apiGet("/me/cv");
    const cv=res && res.cv ? res.cv : null;
    const fileLabel = cv && (cv.cv_filename || cv.cv_path) ? (cv.cv_filename || cv.cv_path) : "";
    if(!fileLabel) throw new Error("No CV found. Please upload a PDF first.");
    if(!String(fileLabel).toLowerCase().endsWith(".pdf")){
      throw new Error("Please upload a PDF version of your CV to run OCR.");
    }

    setBadge("cvStatusBadge","warn","Starting OCR…");
    setProgress(true, 40, "Starting OCR…", "We are extracting text from your PDF.");
    setText("ocrHint","Starting OCR…");
    showRetryOcr(false);

    await apiPostJson("/me/cv/ocr",{});

    setBadge("cvStatusBadge","warn","OCR running…");
    setProgress(true, 55, "OCR in progress…", "We will update automatically.");
    setText("ocrHint","OCR is running…");
    unlockAiWhileOcrRunning();

    startOcrPolling({ startedAt: Date.now() });
  }catch(e){
    showRetryOcr(true);
    setBadge("cvStatusBadge","bad","OCR error");
    setProgress(false, 0, "", "");
    showTopError(e.message||String(e));
    unlockAiFallback("Could not start OCR. You can try generating suggestions anyway, or retry later.");
  }finally{
    if(btn) btn.disabled=false;
  }
}


async function handleAiGenerate({ force=false, background=false } = {}){
  if(!background) clearTopError();

  // If we already have suggestions, return them.
  if(!force && aiGeneratedOnce){
    const t = (aiResult && Array.isArray(aiResult.titles)) ? aiResult.titles : null;
    return t;
  }
  if(!force && tryLoadCachedAiSuggestions()){
    const t = (aiResult && Array.isArray(aiResult.titles)) ? aiResult.titles : null;
    return t;
  }

  $("aiGenerateBtn").disabled = true;
  $("aiApplyBtn").disabled = true;
  $("aiRegenerateLink").style.display = "none";
  aiSelectedTitles = new Set();
  aiResult = null;

  $("aiTitlesWrap").style.display = "none";
  $("aiAltWrap").style.display = "none";
  $("aiAltChips").innerHTML = "";
  $("aiSkillsWrap").style.display = "none";
  $("aiSkillsChips").innerHTML = "";

  setBadge("aiStatusBadge","warn","Generating…");
  setText("aiHint","Reading your CV and generating job title suggestions…");

  try{
    // Best-effort: if OCR has not finished yet, trigger it once before the AI call
    try{
      const cvRes = await apiGet("/me/cv");
      const cv = cvRes && cvRes.cv ? cvRes.cv : null;
      const fileLabel = cv && (cv.cv_filename || cv.cv_path) ? (cv.cv_filename || cv.cv_path) : "";
      const isPdf = String(fileLabel||"").toLowerCase().endsWith(".pdf");
      const sOcr = String(cv?.cv_ocr_status||"").toLowerCase();
      if(isPdf && sOcr !== "done"){
        try{ await apiPostJson("/me/cv/ocr",{}); }catch(_){}
      }
    }catch(_){}

    const res = await apiPostJson("/me/ai/profile-from-cv",{});
    const r = res && res.result ? res.result : null;
    if(!r) throw new Error("AI returned no result");

    // Best-effort: prefill location from CV (if available)
    try{
      const hints = deriveLocationHintsFromAiResult(r);
      setLocationSuggestionUI(hints);

      const locEl = $("locations");
      const cur = locEl ? parseCsv(locEl.value, 20) : [];
      if(!locationsTouched && (!cur || !cur.length) && Array.isArray(hints) && hints.length){
        // Prefill the first (most likely) city; user can edit anytime
        applyLocation(hints[0], { source:"cv", append:false });
      }
    }catch(_){}

    const titles = Array.isArray(r.job_titles)
      ? r.job_titles.map(x=>String(x).trim()).filter(Boolean)
      : [];

    if(!titles.length){
      setBadge("aiStatusBadge","warn","No titles");
      setText("aiHint","No title suggestions returned. Try a PDF CV and OCR first.");
      $("aiGenerateBtn").disabled = false;
      return null;
    }

    const coreSkills = (r.skills && Array.isArray(r.skills.core)) ? r.skills.core.map(x=>String(x).trim()).filter(Boolean) : [];
    const toolSkills = (r.skills && Array.isArray(r.skills.tools)) ? r.skills.tools.map(x=>String(x).trim()).filter(Boolean) : [];
    const supportingSkills = (r.skills && Array.isArray(r.skills.supporting)) ? r.skills.supporting.map(x=>String(x).trim()).filter(Boolean) : [];
    const primaryTitles = Array.isArray(r.primary_job_titles) ? r.primary_job_titles : [];
    const summaryText = String(r.summary||"").trim();
    const seniority = String(r.seniority||"unknown").trim();

    applyAiUiFromTitles(titles);

    // Persist the exact titles into backend (source of truth for Jobs/Dashboard)
    const saved = await saveAiTitlesToBackend(titles);
    if(saved && saved.ok){
      setText("aiHint","Generated automatically and saved to your account. (Optional) Adjust selection, then update job titles below.");
    }

    try{
      localStorage.setItem("jm_ai_profile", JSON.stringify({
        created_at: new Date().toISOString(),
        job_titles: titles.slice(0,15),
        primary_job_titles: primaryTitles.slice(0,7),
        summary: summaryText,
        seniority: seniority,
        skills: {
          core: coreSkills.slice(0,12),
          supporting: supportingSkills.slice(0,10),
          tools: toolSkills.slice(0,10)
        }
      }));
    }catch(_){}

    {
      const chips=[];
      for(const s of coreSkills.slice(0,10)) chips.push(s);
      for(const s of toolSkills.slice(0,8)) chips.push(s);
      const uniq=[];
      const seen=new Set();
      for(const s of chips){
        const k=String(s).toLowerCase();
        if(!k || seen.has(k)) continue;
        seen.add(k);
        uniq.push(s);
      }
      if(uniq.length){
        $("aiSkillsWrap").style.display="block";
        $("aiSkillsChips").innerHTML = uniq.map(s=>'<span class="pill mini">'+escapeHtml(s)+'</span>').join("");
      }
    }

    try{
      const cs=await apiPostJson("/me/ai/cluster-suggestion",{});
      const cm=cs && cs.cluster_match ? cs.cluster_match : null;
      const altRaw = cm && Array.isArray(cm.alternative_titles)
        ? cm.alternative_titles.map(x=>String(x.title||"").trim()).filter(Boolean)
        : [];
      const titleSet = new Set(titles.map(t=>t.toLowerCase()));
      const altUniq=[];
      const seenAlt=new Set();
      for(const t of altRaw){
        const k=t.toLowerCase();
        if(!k || seenAlt.has(k)) continue;
        if(titleSet.has(k)) continue;
        seenAlt.add(k);
        altUniq.push(t);
      }
      if(altUniq.length){
        $("aiAltWrap").style.display="block";
        $("aiAltChips").innerHTML = altUniq.slice(0,6).map(t=>'<span class="pill mini">'+escapeHtml(t)+'</span>').join("");
      }
      try{
        localStorage.setItem("jm_ai_clusters", JSON.stringify({
          created_at: new Date().toISOString(),
          clusters: (cm && Array.isArray(cm.clusters)) ? cm.clusters.slice(0,3) : [],
          alternative_titles: altUniq.slice(0,10)
        }));
      }catch(_){}
    }catch(_){}

    if(lastCvMeta){
      setAiCache({ cvMetaKey: cvMetaKey(lastCvMeta), titles: titles.slice(0,30), created_at: new Date().toISOString() });
    }

    // Background job prefetch (best-effort)
    try{ await maybePrefetchJobs(titles, "ai_generate"); }catch(_){}

    return titles;
  }catch(e){
    setBadge("aiStatusBadge","bad","Failed");
    setText("aiHint","AI generation failed. You can still tailor your CV and fill preferences manually.");

    if(background){
      toast("warn","AI titles", e?.message || "Automatic generation failed. Tap Generate now to retry.");
    }else{
      showTopError(e.message||String(e));
    }

    $("aiGenerateBtn").disabled = false;
    return null;
  }
}

function handleAiRegenerate(){
aiGeneratedOnce=false;
handleAiGenerate({ force:true });
}

function handleAiApplyTitles(){
clearTopError();
if(!aiSelectedTitles || aiSelectedTitles.size===0){
showTopError("No titles selected.");
return;
}
const picked=[...aiSelectedTitles].slice(0,30);

const current=parseCsv($("jobTitles").value,30);
const remaining=current.filter(t => !picked.includes(t));
const merged=[...new Set([...picked, ...remaining])].slice(0,30);

$("jobTitles").value=merged.join(", ");

aiAppliedOnce=true;
aiAppliedTitles=picked.slice(0,12);
renderAiAppliedChips(aiAppliedTitles);

markPrefsDirty();
scheduleAutoSave();
setBadge("aiStatusBadge","good","Applied");
setText("aiHint","Job titles updated. Add your location — preferences auto-save — to enable matched jobs.");

markStep1DoneVisual(true);

const prefs=$("prefsCard");
if(prefs){
prefs.scrollIntoView({ behavior:"smooth", block:"start" });
}
}


/* -------------------------
   Preferences autosave
   - Step 2 is recommended. We store a local draft while the form is incomplete.
   - We only POST /me/profile when it has at least 1 desired title + 1 location.
   ------------------------- */

const PREFS_SIG_KEY = "jm_profile_pref_sig_v1";
const PREFS_DRAFT_KEY = "jm_profile_draft_v1";

let prefsDirty = false;
let prefsSaving = false;
let prefsSaveQueued = false;
let prefsAutoTimer = null;
let lastPrefsSig = "";

function readPrefsDraft(){
  try{
    const raw = lsSafeGet(PREFS_DRAFT_KEY);
    if(!raw) return null;
    const obj = JSON.parse(raw);
    if(!obj || typeof obj !== "object") return null;
    return obj;
  }catch(_){
    return null;
  }
}
function writePrefsDraft(obj){
  try{ lsSafeSet(PREFS_DRAFT_KEY, JSON.stringify(obj || {})); }catch(_){}
}
function clearPrefsDraft(){
  try{ localStorage.removeItem(PREFS_DRAFT_KEY); }catch(_){}
}
function prefsSignature(prefs){
  // Stable signature for "did anything change?"
  try{
    return JSON.stringify({
      desired_titles: prefs.desired_titles || [],
      industries: prefs.industries || [],
      locations: prefs.locations || [],
      countries_allowed: prefs.countries_allowed || [],
      radius_km: (prefs.radius_km === undefined ? null : prefs.radius_km)
    });
  }catch(_){
    return String(Date.now());
  }
}

function collectPrefsFromForm(){
  const userTitles = parseCsv($("jobTitles").value, 30);
  const aiTop = (aiAppliedTitles || []).map(x=>String(x||"").trim()).filter(Boolean);
  const desired_titles = [...new Set([...aiTop, ...userTitles])].slice(0, 30);

  const industries = parseCsv($("industries").value, 30);
  const locations = parseCsv($("locations").value, 20);

  const countries_allowed = [String($("country").value || "DE").trim()].filter(Boolean);

  let radius_km = $("radiusKm").value ? Number($("radiusKm").value) : null;
  if(!Number.isFinite(radius_km)) radius_km = null;

  return { desired_titles, industries, locations, countries_allowed, radius_km };
}

function collectDraftFromForm(){
  // Draft stores exactly what the user typed (even if incomplete).
  return {
    jobTitles: String($("jobTitles").value || ""),
    industries: String($("industries").value || ""),
    locations: String($("locations").value || ""),
    country: String($("country").value || "DE"),
    radiusKm: String($("radiusKm").value || "")
  };
}

function restoreDraftIfHelpful(){
  const d = readPrefsDraft();
  if(!d) return;

  // Only apply to empty fields (never overwrite backend-loaded values)
  try{
    if($("jobTitles") && !String($("jobTitles").value||"").trim() && d.jobTitles) $("jobTitles").value = d.jobTitles;
    if($("industries") && !String($("industries").value||"").trim() && d.industries) $("industries").value = d.industries;
    if($("locations") && !String($("locations").value||"").trim() && d.locations) $("locations").value = d.locations;
    if($("country") && d.country) $("country").value = d.country;
    if($("radiusKm") && !String($("radiusKm").value||"").trim() && d.radiusKm) $("radiusKm").value = d.radiusKm;
  }catch(_){}
}

function markPrefsDirty(){
  prefsDirty = true;
}

function scheduleAutoSave(){
  // Only autosave when we have a session
  if(!session || !session.access_token) return;

  if(prefsAutoTimer) clearTimeout(prefsAutoTimer);
  prefsAutoTimer = setTimeout(() => {
    savePreferences({ silent:true, allowDraft:true }).catch(()=>{});
  }, 850);
}

async function savePreferences(opts = {}){
  const silent = !!opts.silent;
  const allowDraft = (opts.allowDraft !== false);

  // If user hasn't changed anything, do nothing.
  if(!prefsDirty && !opts.force) return { ok:true, skipped:true };

  // Store a local draft immediately (so we never lose typed info)
  writePrefsDraft(collectDraftFromForm());

  const prefs = collectPrefsFromForm();
  const complete = !!(prefs.desired_titles.length && prefs.locations.length);

  if(!complete){
    if(!allowDraft){
      throw new Error("Please enter at least 1 desired job title and 1 location.");
    }
    // Step 2 is recommended, not blocking. Keep a calm status.
    setBadge("saveStatusBadge","warn","Draft");
    prefsDirty = false;
    return { ok:false, draft:true, complete:false };
  }

  if(!lastPrefsSig){
    lastPrefsSig = String(lsSafeGet(PREFS_SIG_KEY) || "");
  }
  const sig = prefsSignature(prefs);

  // Avoid duplicate saves if nothing changed
  if(sig === lastPrefsSig && !opts.force){
    setBadge("saveStatusBadge","good","Saved");
    prefsDirty = false;
    return { ok:true, skipped:true };
  }

  if(prefsSaving){
    prefsSaveQueued = true;
    return { ok:false, queued:true };
  }

  prefsSaving = true;
  setBadge("saveStatusBadge","warn","Saving…");

  const saveBtn = $("saveProfileBtn");
  if(saveBtn) saveBtn.disabled = true;

  try{
    await apiPostJson("/me/profile", prefs);
    await refreshState();

    lastPrefsSig = sig;
    lsSafeSet(PREFS_SIG_KEY, sig);

    // Saved server-side → clear draft
    clearPrefsDraft();

    setBadge("saveStatusBadge","good","Saved");
    lsSetAll(LS.profileDone, "true");
    prefsDirty = false;

    // Best-effort: once profile is saved, background fetch can be more accurate
    try{ maybePrefetchJobs(aiAppliedTitles, "profile_saved"); }catch(_){}

    return { ok:true };
  }catch(e){
    setBadge("saveStatusBadge","bad","Save failed");
    if(!silent) showTopError(e.message || String(e));
    else toast("warn","Save failed","We couldn't save preferences right now. We kept a draft and you can still continue.");
    prefsDirty = true; // keep dirty so we can retry
    return { ok:false, error: e };
  }finally{
    prefsSaving = false;
    if(saveBtn) saveBtn.disabled = false;

    if(prefsSaveQueued){
      prefsSaveQueued = false;
      setTimeout(() => { savePreferences({ silent:true, allowDraft:true, force:true }).catch(()=>{}); }, 80);
    }
  }
}

async function flushAutoSave(){
  if(prefsAutoTimer){ clearTimeout(prefsAutoTimer); prefsAutoTimer = null; }
  return savePreferences({ silent:true, allowDraft:true }).catch(()=>({ ok:false }));
}

async function handleSaveProfile(){
  clearTopError();
  try{
    await savePreferences({ silent:false, allowDraft:false, force:true });
  }catch(e){
    showTopError(e && e.message ? e.message : String(e));
  }
}


/* -------------------------
   Activity log (modal)
   ------------------------- */

function showActivityError(msg){
  if (S && S.showTopError) return S.showTopError("activityError", msg);
  const el = $("activityError");
  if(!el) return;
  if(!msg){ el.style.display = "none"; el.textContent = ""; return; }
  el.style.display = "block";
  el.textContent = String(msg);
}

function showModal(id){
  if (S && S.showModal) return S.showModal(id);
  const el = $(id);
  if(!el) return;
  el.style.display = "flex";
  document.body.classList.add("modalOpen");
}
function hideModal(id){
  if (S && S.hideModal) return S.hideModal(id);
  const el = $(id);
  if(!el) return;
  el.style.display = "none";
  document.body.classList.remove("modalOpen");
}

function fmtWhen(ts){
  try{
    if(!ts) return "—";
    const d = new Date(ts);
    if(!Number.isFinite(d.getTime())) return String(ts);
    return d.toLocaleString();
  }catch(_){
    return String(ts || "—");
  }
}

function activityBadge(t){
  const x = String(t || "").toLowerCase();
  if(x === "applied" || x === "sent") return { cls:"good", label:"Applied" };
  if(x === "rejected") return { cls:"bad", label:"Rejected" };
  if(x === "skipped") return { cls:"warn", label:"Skipped" };
  if(x === "prioritized") return { cls:"prio", label:"Prioritized" };
  if(x === "queued" || x === "new") return { cls:"", label:"Queued" };
  return { cls:"", label: (t ? String(t) : "Event") };
}

function renderActivityList(items, kind){
  const arr = Array.isArray(items) ? items : [];
  if(!arr.length){
    return '<span class="badge warn">No activity yet</span>';
  }

  const html = arr.slice(0, 20).map((row) => {
    const evType = kind === "applications" ? String(row.status || "new") : String(row.event_type || "");
    const b = activityBadge(evType);

    const job = (row && row.job) ? row.job : {};
    const title = String(job.title || "Untitled");
    const company = String(job.company_name || job.company || "—");
    const loc = [job.city || "", job.region || ""].filter(Boolean).join(", ") || "—";
    const when = kind === "applications" ? (row.updated_at || row.created_at) : row.created_at;
    const link = job.apply_url ? String(job.apply_url) : "";

    const titleHtml = link
      ? ('<a href="' + escapeHtml(link) + '" target="_blank" rel="noopener">' + escapeHtml(title) + "</a>")
      : escapeHtml(title);

    let meta = "";
    try{
      if(kind !== "applications" && row.meta && typeof row.meta === "object"){
        if(row.meta.channel) meta = "via " + String(row.meta.channel);
        if(row.meta.reason_code) meta = meta ? (meta + " • reason: " + String(row.meta.reason_code)) : ("reason: " + String(row.meta.reason_code));
      }
    }catch(_){}

    return (
      '<div class="activityItem">'
        + '<div class="activityTop">'
          + '<div class="activityTitle">' + titleHtml + '</div>'
          + '<span class="badge ' + escapeHtml(b.cls) + '">' + escapeHtml(b.label) + '</span>'
        + '</div>'
        + '<div class="activityMeta">'
          + '<span>' + escapeHtml(company) + '</span>'
          + '<span>•</span>'
          + '<span>' + escapeHtml(loc) + '</span>'
          + '<span>•</span>'
          + '<span>' + escapeHtml(fmtWhen(when)) + '</span>'
          + (meta ? ('<span class="mono">• ' + escapeHtml(meta) + '</span>') : '')
        + '</div>'
      + '</div>'
    );
  }).join("");

  return '<div class="activityList">' + html + '</div>';
}

async function loadActivityLog(){
  showActivityError("");
  setHtml("activityWrap", '<div class="modalMonoBox">Loading…</div>');

  const token = session && session.access_token ? String(session.access_token) : "";
  if(!token){
    showActivityError("You are signed out. Please sign in again.");
    setHtml("activityWrap", "");
    return;
  }

  const et = String($("activityFilter")?.value || "").trim();
  const base = String(API_BASE || "").replace(/\/+$/, "");
  const headers = { Authorization: "Bearer " + token };

  // 1) Try timeline endpoint first
  try{
    let url = base + "/me/application-events?limit=20";
    if(et) url += "&event_type=" + encodeURIComponent(et);

    const res = await fetch(url, { method:"GET", headers });
    const text = await res.text().catch(() => "");
    let json = null;
    try{ json = JSON.parse(text); }catch{ json = { raw: text }; }

    if(!res.ok){
      const msg = (json && (json.error || json.message)) ? String(json.error || json.message) : (text || ("HTTP " + res.status));
      throw new Error(msg);
    }

    const items = Array.isArray(json?.data) ? json.data : [];
    setHtml("activityWrap", renderActivityList(items, "events"));
    return;
  }catch(_){
    // fallback below
  }

  // 2) Fallback: applications list
  try{
    const map = { queued:"new", prioritized:"new", applied:"applied", rejected:"rejected", skipped:"skipped", sent:"applied" };
    let url = base + "/me/applications?limit=20";
    if(et && map[et]) url += "&status=" + encodeURIComponent(map[et]);

    const res = await fetch(url, { method:"GET", headers });
    const text = await res.text().catch(() => "");
    let json = null;
    try{ json = JSON.parse(text); }catch{ json = { raw: text }; }

    if(!res.ok){
      const msg = (json && (json.error || json.message)) ? String(json.error || json.message) : (text || ("HTTP " + res.status));
      throw new Error(msg);
    }

    const items = Array.isArray(json?.data) ? json.data : [];
    setHtml("activityWrap", renderActivityList(items, "applications"));
  }catch(e){
    showActivityError(e?.message || String(e));
    setHtml("activityWrap", '<span class="badge bad">Activity failed</span>');
  }
}

function openActivityModal(){
  const dd = $("navAccount");
  if(dd) dd.open = false;
  showModal("activityModal");
  loadActivityLog().catch((e) => showActivityError(e?.message || String(e)));
}

function closeActivityModal(){
  hideModal("activityModal");
  showActivityError("");
}
async function boot(){
try{
clearTopError();
setText("subLine","Checking session…");
supabaseClient = window.supabase.createClient(SUPABASE_URL, SUPABASE_ANON_KEY);
{
  const auth = getAppAuth();
  if(auth?.supabaseClient){
    supabaseClient = auth.supabaseClient;
  }
}



{
  const auth = getAppAuth();
  session = auth && typeof auth.getSession === "function"
    ? await auth.getSession()
    : null;
}
if(!session){
  const s=await supabaseClient.auth.getSession();
  session=s && s.data ? s.data.session : null;
}
if(!session || !session.user || !session.user.email){
window.location.replace("./signup.html");
return;
}

const email=String(session.user.email||"").trim().toLowerCase();
if(!isEmail(email)){
showTopError("Signed in, but email is missing/invalid.");
return;
}

resetLocalStateForNewUser(email);
try{sessionStorage.setItem("sb_access_token",session.access_token);}catch{}
setText("subLine","Signed in as "+email);
applyStandaloneShell(email);
rememberGoogleProviderTokens();
refreshGmailVerifyUi();

// Nav state: show account dropdown, hide sign-in link
try{
  const navAcct = $("navAccount");
  if(navAcct) navAcct.style.display = "";
  const navSignIn = $("navSignIn");
  if(navSignIn) navSignIn.style.display = "none";
  const navLabel = $("navAccountLabel");
  if(navLabel){
    const handle = String(email).split("@")[0] || "Account";
    navLabel.textContent = handle.length > 16 ? (handle.slice(0,16) + "…") : handle;
  }
}catch(_){}


await ensureCustomer(email);
await refreshState();
await loadCvStatusAndUpdateUx();
await loadProfileIntoForm();
if(ENABLE_GMAIL) await maybeFinishPendingGmailVerify();
// Restore any local draft (only fills empty fields)
try{
  restoreDraftIfHelpful();
  const b = $("saveStatusBadge");
  const t = b ? String(b.textContent||"") : "";
  if(t !== "Loaded" && t !== "Saved"){
    const hasAny = !!(String($("jobTitles")?.value||"").trim() || String($("locations")?.value||"").trim());
    if(hasAny) setBadge("saveStatusBadge","warn","Draft");
  }
}catch(_){ }

// If backend already has AI titles (persisted), show them without forcing regeneration
try{
  const prof2 = await apiGet("/me/profile");
  const p2 = prof2 && prof2.profile ? prof2.profile : null;
  const backendAi = p2 && Array.isArray(p2.ai_titles) ? p2.ai_titles : [];
  if(Array.isArray(backendAi) && backendAi.length){
    backendAiTitles = backendAi.slice(0,30);

    // Prefer per-CV cache if available; otherwise show persisted titles
    if(!tryLoadCachedAiSuggestions()){
      applyAiUiFromTitles(backendAiTitles);
    }

    // Best-effort background prefetch (non-blocking)
    try{ maybePrefetchJobs(backendAiTitles, "boot_ai_titles"); }catch(_){}
  }
}catch(_){}


if(ENABLE_GMAIL){
  $("gmailVerifyBtn")?.addEventListener("click", async ()=>{
    try{
      await handleGmailVerifyClick();
    }catch(e){
      refreshGmailVerifyUi();
      showTopError(e?.message || String(e));
    }
  });
  $("gmailSendAgainBtn")?.addEventListener("click", async ()=>{
    try{
      await handleGmailSendAgainClick();
    }catch(e){
      refreshGmailVerifyUi();
      showTopError(e?.message || String(e));
    }
  });
}

$("cvFile").addEventListener("change",handleCvFileSelected);

// Drag & drop + nice picker UI
wireCvDropzone();
$("retryOcrBtn").addEventListener("click",handleRetryOcr);

$("aiGenerateBtn").addEventListener("click",()=>handleAiGenerate({ force:false }));
$("aiRegenerateLink").addEventListener("click",handleAiRegenerate);
$("aiApplyBtn").addEventListener("click",handleAiApplyTitles);

$("jobTitles").addEventListener("input",()=>{
  jobTitlesTouched=true;
  renderAiAppliedChips(aiAppliedTitles);
  markPrefsDirty();
  scheduleAutoSave();
});

$("locations").addEventListener("input",()=>{
  locationsTouched=true;
  markPrefsDirty();
  scheduleAutoSave();
});

// Autosave: other preference fields
try{
  $("industries")?.addEventListener("input", ()=>{ markPrefsDirty(); scheduleAutoSave(); });
  $("country")?.addEventListener("change", ()=>{ markPrefsDirty(); scheduleAutoSave(); });
  $("radiusKm")?.addEventListener("input", ()=>{ markPrefsDirty(); scheduleAutoSave(); });
}catch(_){}


try{
  // Popular city quick picks (makes Step 2 fast)
  const popular = ["Berlin","Hamburg","München","Frankfurt","Köln","Stuttgart","Düsseldorf","Leipzig"];
  renderClickChips("locQuickChips", popular, (label)=>{
    applyLocation(label, { append:false });
  });
}catch(_){}

try{
  // Radius quick picks
  document.querySelectorAll("#radiusQuick .chip[data-radius]").forEach((chip)=>{
    chip.addEventListener("click", ()=>{
      const v = Number(chip.getAttribute("data-radius") || "");
      if(Number.isFinite(v)){
        $("radiusKm").value = String(v);
        markPrefsDirty();
scheduleAutoSave();
      }
    });
  });
}catch(_){}

const _saveBtn = $("saveProfileBtn");
if(_saveBtn){ _saveBtn.addEventListener("click", handleSaveProfile); }
$("continueBtn").addEventListener("click", async ()=>{
  const cvOk = !!(state && state.cv_uploaded);

  if(!cvOk){
    $("step1Card")?.scrollIntoView({ behavior:"smooth", block:"start" });
    toast("warn","Upload CV","Please upload your CV first.");
    return;
  }

  const btn = $("continueBtn");
  const old = btn ? btn.textContent : "";
  try{
    if(btn){ btn.disabled = true; btn.textContent = "Saving…"; }
    await flushAutoSave();
  }catch(_){
    // keep calm; draft is still stored
  }finally{
    if(btn){ btn.textContent = old || "Open CV Studio"; btn.disabled = false; }
  }

  go("./cv.html");
});
{
  const b = $("openCvBtn");
  if(b){
    b.addEventListener("click", async ()=>{
      const cvOk = !!(state && state.cv_uploaded);
      if(!cvOk){
        $("step1Card")?.scrollIntoView({ behavior:"smooth", block:"start" });
        toast("warn","Upload CV","Please upload your CV first.");
        return;
      }
      try{ await flushAutoSave(); }catch(_){}
      go("./cv.html");
    });
  }
}
// Account dropdown actions
$("navActivity")?.addEventListener("click", openActivityModal);
$("activityCloseX")?.addEventListener("click", closeActivityModal);
$("activityClose")?.addEventListener("click", closeActivityModal);
$("activityModal")?.addEventListener("click", (e) => { if(e.target && e.target.id === "activityModal") closeActivityModal(); });
$("activityRefresh")?.addEventListener("click", () => loadActivityLog().catch(()=>{}));
$("activityFilter")?.addEventListener("change", () => loadActivityLog().catch(()=>{}));

$("navLogout")?.addEventListener("click", async ()=>{
  try{
    const auth = getAppAuth();
    if(auth?.logout){
      await auth.logout("./index.html");
      return;
    }
  }catch(_){}

  // Fallback: sign out via supabase client
  try{ await supabaseClient?.auth?.signOut(); }catch(_){}

  // Best-effort cleanup (keep sb_* keys intact if auth.js is managing them)
  try{
    Object.keys(localStorage).forEach(k=>{
      if(k.startsWith("ja_") || k.startsWith("jobapplyai_") || k.startsWith("jm_") || k.startsWith("jobmejob_")){
        localStorage.removeItem(k);
      }
    });
  }catch(_){}
  try{
    Object.keys(sessionStorage).forEach(k=>{
      if(k === "sb_access_token" || k.startsWith("ja_") || k.startsWith("jobapplyai_") || k.startsWith("jm_") || k.startsWith("jobmejob_")){
        sessionStorage.removeItem(k);
      }
    });
  }catch(_){}

  window.location.replace("./index.html");
});
}catch(e){
showTopError(e.message||String(e));
}
}

window.addEventListener("beforeunload",()=>{try{stopOcrPollingAndCleanup();}catch{}});
window.addEventListener("load",boot);
