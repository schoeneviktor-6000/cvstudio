import {
  buildStudioImportUrl,
  normalizeImportPayload,
  scrapeJobPostingPage,
  truncateText
} from "./scraper.js";

let activeTab = null;
let lastPayload = null;
let refreshTimer = null;

function $(id){
  return document.getElementById(id);
}

function setText(id, value){
  const el = $(id);
  if(el) el.textContent = String(value ?? "");
}

function setStatus(message){
  setText("status", message);
}

function setError(message){
  const el = $("error");
  if(!el) return;
  if(!message){
    el.style.display = "none";
    el.textContent = "";
    return;
  }
  el.style.display = "block";
  el.textContent = String(message);
}

function updateButtons(){
  const desc = String($("jobDescription")?.value || "").trim();
  $("copyBtn").disabled = !desc;
  $("openBtn").disabled = !desc;
}

function originPatternForUrl(url){
  try{
    const u = new URL(String(url || ""));
    if(!/^https?:$/i.test(u.protocol)) return "";
    return u.origin + "/*";
  }catch(_){
    return "";
  }
}

function hostnameForUrl(url){
  try{
    return new URL(String(url || "")).hostname || "";
  }catch(_){
    return "";
  }
}

function isPermissionError(err){
  const msg = String(err && err.message ? err.message : err || "").toLowerCase();
  return (
    msg.includes("cannot access contents of the page") ||
    msg.includes("missing host permission") ||
    msg.includes("cannot access a chrome:// url") ||
    msg.includes("the extensions gallery cannot be scripted")
  );
}

function updateSummary(payload){
  const p = payload && typeof payload === "object" ? payload : null;
  if(!p){
    setText("platform", "-");
    setText("charCount", "0 chars");
    setText("sourceHost", "-");
    return;
  }
  setText("platform", truncateText(p.platform || "generic", 18));
  setText("charCount", String((p.description || "").length) + " chars");
  setText("sourceHost", p.source_host || "-");
}

function fillForm(payload){
  const p = payload && typeof payload === "object" ? payload : null;
  $("jobTitle").value = p ? String(p.title || "") : "";
  $("jobCompany").value = p ? String(p.company || "") : "";
  $("jobUrl").value = p ? String(p.apply_url || "") : "";
  $("jobDescription").value = p ? String(p.description || "") : "";
  updateSummary(p);
  updateButtons();
}

function readFormPayload(){
  const jobUrl = $("jobUrl").value;
  return normalizeImportPayload({
    title: $("jobTitle").value,
    company: $("jobCompany").value,
    apply_url: jobUrl,
    source_host: hostnameForUrl(jobUrl) || hostnameForUrl(activeTab?.url),
    platform: lastPayload?.platform || "generic",
    language_hint: lastPayload?.language_hint || "auto",
    page_title: lastPayload?.page_title || "",
    description: $("jobDescription").value
  });
}

async function queryActiveTab(){
  const tabs = await chrome.tabs.query({ active: true, lastFocusedWindow: true });
  return tabs && tabs.length ? tabs[0] : null;
}

async function requestOriginPermission(url){
  const pattern = originPatternForUrl(url);
  if(!pattern) return false;
  return chrome.permissions.request({ origins: [pattern] });
}

async function scrapeCurrentTab(opts = {}){
  const allowPermissionRequest = !!(opts && opts.allowPermissionRequest);
  setError("");
  setStatus("Scraping the active job page…");

  activeTab = await queryActiveTab();
  if(!activeTab || typeof activeTab.id !== "number"){
    throw new Error("Could not find the active browser tab.");
  }

  const url = String(activeTab.url || "");
  setText("pageUrl", url || "Unknown URL");

  if(!/^https?:/i.test(url)){
    throw new Error("Open a normal job posting page first. Chrome pages and local files cannot be scraped.");
  }

  let results;
  try{
    results = await chrome.scripting.executeScript({
      target: { tabId: activeTab.id },
      func: scrapeJobPostingPage
    });
  }catch(err){
    if(allowPermissionRequest && isPermissionError(err)){
      const granted = await requestOriginPermission(url);
      if(!granted){
        throw new Error("Permission was not granted for this site. Click the action icon on the job page or approve the site permission to scrape it.");
      }
      results = await chrome.scripting.executeScript({
        target: { tabId: activeTab.id },
        func: scrapeJobPostingPage
      });
    }else{
      throw err;
    }
  }

  const payload = results && results[0] ? results[0].result : null;
  if(!payload || !String(payload.description || "").trim()){
    throw new Error("No meaningful job description text was found on this page.");
  }

  lastPayload = normalizeImportPayload(payload);
  fillForm(lastPayload);
  setStatus("Scrape complete. Review the text, then open CV Studio.");
}

function scheduleRefresh(reason){
  if(!$("autoRefresh").checked) return;
  if(refreshTimer) clearTimeout(refreshTimer);
  refreshTimer = setTimeout(async () => {
    try{
      activeTab = await queryActiveTab();
      setText("pageUrl", activeTab?.url || "No active tab");
      await scrapeCurrentTab({ allowPermissionRequest: false });
      setStatus("Auto-refreshed after " + reason + ".");
    }catch(err){
      fillForm(null);
      if(isPermissionError(err)){
        setStatus("This tab needs permission before it can be scraped. Click “Scrape current tab” to grant access.");
        setError("");
        return;
      }
      setError(err && err.message ? err.message : String(err));
    }
  }, 250);
}

async function copyDescription(){
  const text = String($("jobDescription").value || "").trim();
  if(!text) return;
  await navigator.clipboard.writeText(text);
  setStatus("Copied the extracted job description.");
}

async function openInStudio(){
  const payload = readFormPayload();
  if(!payload.description){
    throw new Error("Scrape a job page or paste a job description first.");
  }
  const url = buildStudioImportUrl(payload);
  await chrome.tabs.create({ url });
  setStatus("Opening CV Studio with the current job description…");
}

function wireTabListeners(){
  chrome.tabs.onActivated.addListener(() => {
    scheduleRefresh("tab switch");
  });

  chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
    if(!activeTab || tabId !== activeTab.id) return;
    if(changeInfo.status === "complete"){
      scheduleRefresh("page load");
    }
  });
}

async function init(){
  fillForm(null);
  $("jobDescription").addEventListener("input", updateButtons);
  $("rescrapeBtn").addEventListener("click", async () => {
    try{
      await scrapeCurrentTab({ allowPermissionRequest: true });
    }catch(err){
      fillForm(null);
      setError(err && err.message ? err.message : String(err));
      setStatus("Scrape failed.");
    }
  });
  $("copyBtn").addEventListener("click", async () => {
    try{
      await copyDescription();
    }catch(err){
      setError(err && err.message ? err.message : String(err));
    }
  });
  $("openBtn").addEventListener("click", async () => {
    try{
      await openInStudio();
    }catch(err){
      setError(err && err.message ? err.message : String(err));
    }
  });

  wireTabListeners();

  try{
    await scrapeCurrentTab({ allowPermissionRequest: false });
  }catch(err){
    fillForm(null);
    activeTab = await queryActiveTab();
    setText("pageUrl", activeTab?.url || "No active tab");
    if(isPermissionError(err)){
      setError("");
      setStatus("This tab needs permission before it can be scraped. Click “Scrape current tab” to grant access.");
      return;
    }
    setError(err && err.message ? err.message : String(err));
    setStatus("Scrape failed.");
  }
}

document.addEventListener("DOMContentLoaded", init);
