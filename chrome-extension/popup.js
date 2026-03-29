"use strict";

const STUDIO_IMPORT_URL = "https://cvstudio.work/extension-bridge.html#import=";
const MAX_DESCRIPTION_CHARS = 20000;

let activeTab = null;
let lastPayload = null;

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

function setButtonsEnabled(enabled){
  $("copyBtn").disabled = !enabled;
  $("openBtn").disabled = !enabled;
}

function truncateText(value, max){
  const text = String(value || "");
  if(text.length <= max) return text;
  return text.slice(0, Math.max(0, max - 1)) + "…";
}

function base64UrlEncodeUtf8(value){
  const bytes = new TextEncoder().encode(String(value || ""));
  let binary = "";
  const chunkSize = 0x8000;
  for(let i = 0; i < bytes.length; i += chunkSize){
    binary += String.fromCharCode(...bytes.subarray(i, i + chunkSize));
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function scrapeJobPostingPage(){
  const DESCRIPTION_SELECTORS = [
    ".jobs-description-content__text",
    ".jobs-box__html-content",
    ".show-more-less-html__markup",
    ".jobs-description__container",
    ".jobs-description",
    ".description__text",
    ".jobDescriptionText",
    ".jobDescriptionContent",
    ".jobsearch-JobComponent-description",
    ".jobsearch-jobDescriptionText",
    ".job-description",
    ".job-description-container",
    ".posting-page",
    ".content.intro + .content",
    "[data-testid='job-details']",
    "[data-testid='jobDescriptionText']",
    "[data-test='job-description']",
    "[data-qa='job-description']",
    "[data-ui='job-description']",
    "main",
    "article",
    "[role='main']"
  ];

  const TITLE_SELECTORS = [
    ".job-details-jobs-unified-top-card__job-title",
    ".jobs-unified-top-card__job-title",
    ".top-card-layout__title",
    ".jobsearch-JobInfoHeader-title",
    "[data-testid='job-title']",
    "main h1",
    "article h1",
    "h1"
  ];

  const COMPANY_SELECTORS = [
    ".job-details-jobs-unified-top-card__company-name",
    ".jobs-unified-top-card__company-name",
    ".topcard__org-name-link",
    ".jobsearch-InlineCompanyRating div:first-child",
    "[data-testid='company-name']",
    "[data-company-name]",
    ".company",
    ".employer"
  ];

  function truncateLocal(value, max){
    const text = String(value || "");
    if(text.length <= max) return text;
    return text.slice(0, Math.max(0, max - 1)) + "…";
  }

  function normalizeExtractedText(text){
    const raw = String(text || "").replace(/\r/g, "");
    const lines = raw
      .split("\n")
      .map((line) => line.replace(/\s+/g, " ").trim())
      .filter(Boolean);

    const deduped = [];
    for(const line of lines){
      const prev = deduped[deduped.length - 1];
      if(prev && prev === line) continue;
      deduped.push(line);
    }

    return deduped.join("\n").trim();
  }

  function readDescriptionCandidate(selectors){
    const values = [];
    for(const selector of selectors){
      const nodes = document.querySelectorAll(selector);
      for(const node of nodes){
        const text = normalizeExtractedText(node.innerText || node.textContent || "");
        if(text.length >= 120) values.push(text);
      }
    }
    values.sort((a, b) => b.length - a.length);
    return values[0] || "";
  }

  function meta(selector, attr = "content"){
    const el = document.querySelector(selector);
    return el ? String(el.getAttribute(attr) || "").trim() : "";
  }

  function firstText(selectors){
    for(const selector of selectors){
      const el = document.querySelector(selector);
      if(!el) continue;
      const text = normalizeExtractedText(el.innerText || el.textContent || "");
      if(text) return text;
    }
    return "";
  }

  function fallbackDescription(){
    const candidates = Array.from(document.querySelectorAll("section, div, main, article"))
      .map((node) => normalizeExtractedText(node.innerText || node.textContent || ""))
      .filter((text) => text.length >= 300)
      .sort((a, b) => b.length - a.length);

    return candidates[0] || normalizeExtractedText(document.body.innerText || "");
  }

  const title =
    firstText(TITLE_SELECTORS) ||
    meta("meta[property='og:title']") ||
    String(document.title || "").replace(/\s+[|\-:]\s+.+$/, "").trim();

  const company =
    firstText(COMPANY_SELECTORS) ||
    meta("meta[name='og:site_name']") ||
    meta("meta[property='og:site_name']");

  let description = readDescriptionCandidate(DESCRIPTION_SELECTORS);
  if(!description) description = fallbackDescription();
  description = normalizeExtractedText(description).slice(0, MAX_DESCRIPTION_CHARS);

  return {
    title: truncateLocal(title || "Untitled role", 180),
    company: truncateLocal(company, 140),
    apply_url: String(window.location.href || "").trim(),
    source_host: String(window.location.hostname || "").trim(),
    language_hint: String(document.documentElement.lang || "auto").split("-")[0] || "auto",
    description,
    page_title: String(document.title || "").trim()
  };
}

function updateSummary(payload){
  const p = payload && typeof payload === "object" ? payload : null;
  if(!p){
    setText("jobTitle", "No scrape yet.");
    setText("jobMeta", "Use LinkedIn, Greenhouse, Lever, Indeed, Workday, or any company careers page.");
    setText("charCount", "0 chars");
    setText("sourceHost", "-");
    setButtonsEnabled(false);
    return;
  }

  setText("jobTitle", p.title || "Untitled role");
  setText("jobMeta", [p.company || "", p.apply_url || ""].filter(Boolean).join(" • ") || "Current page");
  setText("charCount", (p.description || "").length + " chars");
  setText("sourceHost", p.source_host || "-");
  setButtonsEnabled(!!String(p.description || "").trim());
}

async function getActiveTab(){
  const tabs = await chrome.tabs.query({ active: true, lastFocusedWindow: true });
  return tabs && tabs.length ? tabs[0] : null;
}

async function scrapeActiveTab(){
  setError("");
  setStatus("Scraping the current page…");

  activeTab = await getActiveTab();
  if(!activeTab || !activeTab.id){
    throw new Error("Could not find the active browser tab.");
  }

  const url = String(activeTab.url || "");
  setText("pageUrl", url || "Unknown URL");

  if(!/^https?:/i.test(url)){
    throw new Error("Open a normal job posting page first. Chrome pages and local files cannot be scraped.");
  }

  const results = await chrome.scripting.executeScript({
    target: { tabId: activeTab.id },
    func: scrapeJobPostingPage
  });

  const payload = results && results[0] ? results[0].result : null;
  if(!payload || !String(payload.description || "").trim()){
    throw new Error("No meaningful job description text was found on this page.");
  }

  lastPayload = payload;
  updateSummary(payload);
  setStatus("Job page scraped. Open CV Studio when you are ready.");
}

async function copyExtractedText(){
  if(!lastPayload || !lastPayload.description) return;
  await navigator.clipboard.writeText(lastPayload.description);
  setStatus("Copied the extracted job description to your clipboard.");
}

async function openInStudio(){
  if(!lastPayload || !lastPayload.description){
    throw new Error("Scrape a job page first.");
  }

  const encoded = base64UrlEncodeUtf8(JSON.stringify(lastPayload));
  const url = STUDIO_IMPORT_URL + encodeURIComponent(encoded);
  await chrome.tabs.create({ url });
  setStatus("Opening CV Studio with the scraped job description…");
}

async function init(){
  $("rescrapeBtn").addEventListener("click", async () => {
    try{
      await scrapeActiveTab();
    }catch(err){
      updateSummary(null);
      setError(err && err.message ? err.message : String(err));
      setStatus("Scrape failed.");
    }
  });

  $("copyBtn").addEventListener("click", async () => {
    try{
      await copyExtractedText();
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

  try{
    await scrapeActiveTab();
  }catch(err){
    updateSummary(null);
    setError(err && err.message ? err.message : String(err));
    setStatus("Scrape failed.");
  }
}

document.addEventListener("DOMContentLoaded", init);
