/* shared.js — JobMeJob multipage helpers (site-wide)
   Version: 2026-01-27 (v3)

   Safe to include on every page.
   Includes:
   - nav transitions (nice page feel)
   - details dropdown auto-close (Account dropdown etc.)
   - modal open/close + ESC + backdrop click
   - toast notifications
   - clipboard copy helper
   - API_BASE resolver
   - (optional) global setStudioMode (only defined if missing)
*/
(() => {
  "use strict";

  // Avoid double-init
  if ((window.CVStudioShared && window.CVStudioShared.__loaded_v3) || (window.JobMeJobShared && window.JobMeJobShared.__loaded_v3)) return;

  const VERSION = "2026-01-27-v3";

  const $ = (id) => document.getElementById(id);
  const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

  function escapeHtml(s){
    const map = { "&":"&amp;", "<":"&lt;", ">":"&gt;", '"':"&quot;", "'":"&#39;" };
    return String(s ?? "").replace(/[&<>"']/g, (c) => map[c] || c);
  }

  function safeLocalGet(key){
    try { return localStorage.getItem(key); } catch { return null; }
  }
  function safeLocalSet(key, val){
    try { localStorage.setItem(key, val); } catch {}
  }

  function isLocalDebugHost(){
    try{
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
    }catch(_){
      return false;
    }
  }

  function prefersReducedMotion(){
    try{
      return window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    }catch(_){
      return false;
    }
  }

  function normalizeBaseUrl(u){
    return String(u || "").trim().replace(/\/+$/, "");
  }

  function resolveApiBase(fallback){
    // Production pages must ignore client-controlled API overrides.
    const allowDebugOverride = isLocalDebugHost();
    let qp = "";
    if (allowDebugOverride){
      try{
        const u = new URL(window.location.href);
        qp = normalizeBaseUrl(u.searchParams.get("api") || "");
      }catch(_){}
    }

    const apiOverride = allowDebugOverride
      ? normalizeBaseUrl(safeLocalGet("jm_api_base") || safeLocalGet("ja_api_base"))
      : "";

    // Base set by auth.js/pages
    const appConfig =
      (window.CVStudio && window.CVStudio.config)
        ? window.CVStudio.config
        : ((window.JobMeJob && window.JobMeJob.config)
          ? window.JobMeJob.config
          : ((window.JobApplyAI && window.JobApplyAI.config) ? window.JobApplyAI.config : null));
    const apiFromWindow =
      (appConfig && appConfig.API_BASE)
        ? normalizeBaseUrl(appConfig.API_BASE)
        : "";

    return qp || apiOverride || apiFromWindow || normalizeBaseUrl(fallback);
  }

  function go(url){
    if(!url) return;
    const href = String(url);

    if (prefersReducedMotion()){
      window.location.href = href;
      return;
    }

    try{ document.body.classList.add("leaving"); }catch(_){}
    setTimeout(() => { window.location.href = href; }, 160);
  }

  function wireNavTransitions(){
    if (wireNavTransitions.__wired) return;
    wireNavTransitions.__wired = true;

    document.addEventListener("click", (e) => {
      const a = e.target && e.target.closest ? e.target.closest("a[data-nav='1']") : null;
      if(!a) return;

      // allow new tab clicks
      if (e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;

      const url = a.getAttribute("href");
      if(!url || url.startsWith("#")) return;

      // external links: normal behavior
      if(/^https?:\/\//i.test(url)) return;

      // explicit new tab
      if (a.getAttribute("target") === "_blank") return;

      e.preventDefault();
      go(url);
    });
  }

  function wireDetailsDropdowns(selector = "details.navDrop, details.studioDrop, details[data-dd='1']"){
    if (wireDetailsDropdowns.__wired) return;
    wireDetailsDropdowns.__wired = true;

    const closeAll = (except) => {
      $$(selector).forEach(d => { if(d !== except) d.open = false; });
    };

    document.addEventListener("click", (e) => {
      const openDrop = e.target && e.target.closest ? e.target.closest(selector) : null;

      if(openDrop){
        closeAll(openDrop);

        // If clicked a menu item (not summary), close after click.
        const sum = openDrop.querySelector("summary");
        const clickedSummary = sum && (e.target === sum || (e.target && sum.contains(e.target)));
        if(!clickedSummary){
          const isItem = e.target && e.target.closest ? e.target.closest("a,button") : null;
          if(isItem) setTimeout(() => { openDrop.open = false; }, 0);
        }
        return;
      }
      closeAll(null);
    });

    document.addEventListener("keydown", (e) => {
      if (e.key === "Escape") closeAll(null);
    });
  }

  // Backwards alias (some pages call this)
  function wireNavDropdowns(){
    return wireDetailsDropdowns("details.navDrop, details[data-dd='1']");
  }

  function showTopError(idOrMsg, maybeMsg){
    let id = "errorTop";
    let msg = idOrMsg;

    if (typeof maybeMsg !== "undefined"){
      id = String(idOrMsg || "errorTop");
      msg = maybeMsg;
    }

    const el = $(id);
    if(!el) return;

    const m = String(msg ?? "");
    if(!m){
      el.style.display = "none";
      el.textContent = "";
      return;
    }
    el.style.display = "block";
    el.textContent = m;
  }

  function setBadge(id, cls, text){
    const el = $(id);
    if(!el) return;
    el.className = "badge" + (cls ? (" " + cls) : "");
    el.textContent = String(text ?? "");
  }

  function showModal(id){
    const el = $(id);
    if(!el) return;
    el.style.display = "flex";
    try{ document.body.classList.add("modalOpen"); }catch(_){}
  }

  function hideModal(id){
    const el = $(id);
    if(!el) return;
    el.style.display = "none";
    try{
      const anyOpen = $$(".modalBackdrop").some(m => window.getComputedStyle(m).display !== "none");
      if(!anyOpen) document.body.classList.remove("modalOpen");
    }catch(_){
      try{ document.body.classList.remove("modalOpen"); }catch(__){}
    }
  }

  function wireModalDismiss(){
    if (wireModalDismiss.__wired) return;
    wireModalDismiss.__wired = true;

    // Click on backdrop closes modal (only if click is directly on backdrop)
    document.addEventListener("click", (e) => {
      const backdrop = e.target && e.target.classList && e.target.classList.contains("modalBackdrop")
        ? e.target
        : null;
      if(!backdrop) return;
      if (e.target !== backdrop) return;

      const id = backdrop.getAttribute("id");
      if(id) hideModal(id);
    });

    // [data-close-modal] closes the nearest modalBackdrop
    document.addEventListener("click", (e) => {
      const btn = e.target && e.target.closest ? e.target.closest("[data-close-modal]") : null;
      if(!btn) return;
      const m = btn.closest(".modalBackdrop");
      if(m && m.id) hideModal(m.id);
    });

    // ESC closes the latest-open modal
    document.addEventListener("keydown", (e) => {
      if(e.key !== "Escape") return;
      const open = $$(".modalBackdrop").filter(m => window.getComputedStyle(m).display !== "none");
      const last = open[open.length - 1];
      if(last && last.id) hideModal(last.id);
    });
  }

  function ensureToastWrap(){
    let wrap = document.querySelector(".toastWrap");
    if(wrap) return wrap;
    wrap = document.createElement("div");
    wrap.className = "toastWrap";
    wrap.setAttribute("aria-live","polite");
    document.body.appendChild(wrap);
    return wrap;
  }

  function toast(message, opts = {}){
    const wrap = ensureToastWrap();
    const el = document.createElement("div");
    const kind = String(opts.kind || "").trim(); // good | warn | bad | ""
    el.className = "toast" + (kind ? (" " + kind) : "");
    const title = opts.title ? `<div class="t">${escapeHtml(opts.title)}</div>` : "";
    el.innerHTML = title + `<div>${escapeHtml(message || "")}</div>`;
    wrap.appendChild(el);

    const ms = Number.isFinite(opts.ms) ? Number(opts.ms) : 2600;
    setTimeout(() => {
      try { el.style.opacity = "0"; el.style.transform = "translateY(6px)"; } catch(_){}
      setTimeout(() => { try { el.remove(); } catch(_){ } }, 220);
    }, ms);
  }

  async function copyToClipboard(text){
    const t = String(text ?? "");
    if(!t) return false;
    try{
      await navigator.clipboard.writeText(t);
      return true;
    }catch(_){
      try{
        const ta = document.createElement("textarea");
        ta.value = t;
        ta.style.position = "fixed";
        ta.style.left = "-9999px";
        ta.style.top = "0";
        document.body.appendChild(ta);
        ta.focus();
        ta.select();
        const ok = document.execCommand("copy");
        ta.remove();
        return !!ok;
      }catch(__){
        return false;
      }
    }
  }

  // ------------------------------------------------------------
  // CV Studio helper (global): setStudioMode
  // Only define if missing to avoid overriding cv.html's own implementation.
  // ------------------------------------------------------------
  function defaultSetStudioMode(mode, opts = {}){
    const m = String(mode || "tailor").trim().toLowerCase() || "tailor";
    const rootId = String(opts.rootId || "studioRoot");
    const root = $(rootId) || document.querySelector("[data-studio-root]");
    if(root) root.setAttribute("data-mode", m);

    safeLocalSet("jmj_cv_mode", m);

    $$("[data-studio-mode]").forEach((el) => {
      const em = String(el.getAttribute("data-studio-mode") || "").trim().toLowerCase();
      const on = em === m;
      el.classList.toggle("active", on);
      try{ el.setAttribute("aria-selected", on ? "true" : "false"); }catch(_){}
    });

    try{
      window.dispatchEvent(new CustomEvent("jmj:studioMode", { detail: { mode: m } }));
    }catch(_){}

    return m;
  }

  if (typeof window.setStudioMode !== "function"){
    window.setStudioMode = defaultSetStudioMode;
  }

  // Export shared API (merge with existing)
  const api = {
    __loaded_v3: true,
    VERSION,

    $,
    $$,
    escapeHtml,

    safeLocalGet,
    safeLocalSet,
    isLocalDebugHost,

    normalizeBaseUrl,
    resolveApiBase,

    go,
    wireNavTransitions,
    wireDetailsDropdowns,
    wireNavDropdowns,

    showTopError,
    setBadge,

    showModal,
    hideModal,
    wireModalDismiss,

    toast,
    copyToClipboard,

    setStudioMode: window.setStudioMode
  };

  const sharedApi = Object.assign({}, window.CVStudioShared || window.JobMeJobShared || {}, api);
  window.CVStudioShared = sharedApi;
  window.JobMeJobShared = sharedApi;

  const app = window.CVStudio || window.JobMeJob || window.JobApplyAI || {};
  window.CVStudio = app;
  window.JobMeJob = app;
  window.JobApplyAI = app;
  app.shared = sharedApi;

  // Auto-wire global behaviors
  window.addEventListener("DOMContentLoaded", () => {
    wireNavTransitions();
    wireDetailsDropdowns();
    wireModalDismiss();
  });
})();
