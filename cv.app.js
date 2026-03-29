  (() => {
    "use strict";

    const S = window.CVStudioShared || window.JobMeJobShared || null;
    const APP_CONFIG = window.CVStudio?.config || window.JobMeJob?.config || window.JobApplyAI?.config || null;
    function getAppAuth(){
      return window.CVStudio?.auth || window.JobMeJob?.auth || window.JobApplyAI?.auth || null;
    }
    const FEATURES = (APP_CONFIG && (APP_CONFIG.FEATURES || APP_CONFIG.features)) || {};
    const STANDALONE_MODE = !!(APP_CONFIG && (APP_CONFIG.STANDALONE || APP_CONFIG.standalone || FEATURES.standalone));

    // Fallbacks (so one missing helper doesn't break the whole page)
    const F = {
      escapeHtml: (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;" }[c])),
      showModal: (id) => { const el = document.getElementById(id); if(el) el.style.display=""; },
      hideModal: (id) => { const el = document.getElementById(id); if(el) el.style.display="none"; },
      showTopError: (id, msg) => { const el = document.getElementById(id); if(el){ el.textContent = msg||""; el.style.display = msg ? "" : "none"; } },
      setBadge: (id, cls, txt) => {
        const el = document.getElementById(id); if(!el) return;
        el.className = "badge" + (cls ? (" " + cls) : "");
        el.textContent = txt ?? "";
      },
      resolveApiBase: (x) => String(x || "").trim()
    };

    const H = {
      escapeHtml: S?.escapeHtml ? S.escapeHtml : F.escapeHtml,
      showModal: S?.showModal ? S.showModal : F.showModal,
      hideModal: S?.hideModal ? S.hideModal : F.hideModal,
      showTopError: S?.showTopError ? S.showTopError : F.showTopError,
      setBadge: S?.setBadge ? S.setBadge : F.setBadge,
      resolveApiBase: S?.resolveApiBase ? S.resolveApiBase : F.resolveApiBase,
      wireNavTransitions: S?.wireNavTransitions ? S.wireNavTransitions.bind(S) : (()=>{})
    };

    H.wireNavTransitions();

    const $ = (id) => document.getElementById(id);

    const API_BASE = (APP_CONFIG && APP_CONFIG.API_BASE
      ? String(APP_CONFIG.API_BASE)
      : H.resolveApiBase("https://jobmejob.schoene-viktor.workers.dev")
    ).replace(/\/+$/, "");

    let session = null;
    let jobs = [];
    let selectedJob = null;
    let selectedDesc = "";
    let selectedApplyUrl = "";
    const EXT_IMPORT_KEY = "cvstudio_extension_import_v1";
    const EXT_IMPORT_MAX_DESC = 20000;

    // Job source: queue (your saved jobs) vs paste (manual job description)
    let jobSource = STANDALONE_MODE ? "paste" : "queue"; // "queue" | "paste"
    let pasteDraft = { title:"", company:"", apply:"", lang_hint:"auto", desc:"" };
let pasteCacheKey = "";
let pendingExtensionImport = null;

// UI: collapsible Setup panel (focus mode)
let setupCollapsed = false;
let setupUserToggled = false;
let setupAutoCollapsedOnce = false;

// UI: generation steps modal (auto-open while generating)
let genModalAuto = false;
let genStepsState = "idle";


    let lastCvText = "";
    let lastCvDoc = null;
    let lastLang = "en";

    // Keyword tracking
    let atsKeywordsAll = [];     // full list from server (union)
    let lastUsed = [];
    let lastMissing = [];
    let lastDebug = {};

    // Edits
    let baseSnapshot = null;
    let historyStack = [];

    // Keyword modal state
    let activeKeywordRaw = "";
    let activeKeywordDisplay = "";
    let kwMode = "ai"; // ai | quick

    // AI placement recommendation (cached per CV+keyword)
    let kwAiReco = null; // { target, exp_index, bullet_index, rewritten_bullet, skill_group, skill_item, reason, confidence }
    let kwAiRecoKey = "";
    const kwAiRecoCache = new Map();
    let kwAiKeywordPretty = "";
    let kwAiRecoToken = 0;

    // "Rewrite again" variants (per keyword + language + selected bullet)
    let kwRewriteVariants = [];   // [{ text, at }]
    let kwRewriteSelected = "reco"; // "reco" or "v:<index>"
    let kwRewriteKey = "";
    let kwRewriteToken = 0;

    // Final QA state (local checks)
    let qaLastRunAt = 0;
    let qaLastHash = "";
    let qaLastReport = null;
    let qaPendingAction = ""; // "", "print", "download"

    // UI language (interface). Keep English UI; keyword insertion language follows your CV language (auto).
    let uiLang = "en";

    /* -------------------------
       i18n (interface)
       ------------------------- */
    const I18N = {
      de: {
        subTitle: "Fuege eine Stellenbeschreibung ein und passe deinen CV ATS-sicher daran an.",
        setupTitle: "Setup",
        jobToTailorLbl: "Job auswählen",
        openJobsBtn: "Jobs öffnen",
        btnViewDesc: "Beschreibung ansehen",
        btnCopyDesc: "Beschreibung kopieren",
        templateLbl: "Template",
        atsHintLine: "ATS-sicher = einfache Überschriften, keine Tabellen/Spalten, leicht zu parsen.",
        tailorStrengthLbl: "Tailoring-Stärke",
        light: "Leicht",
        balanced: "Balanced",
        aggressive: "Aggressiv",
        gen: "Tailored CV generieren",
        genAgain: "Neu generieren",
        stepsTitle: "So funktioniert’s",
        stepsIntro: "Das passiert, wenn du auf „Generieren“ klickst:",
        s1: "Job-Keywords extrahieren",
        s2: "Summary & Bullets anpassen",
        s3: "ATS-sichere Struktur beibehalten",
        s4: "ATS Match berechnen",
        s5: "Preview & Export vorbereiten",
        truthHint: "Wir bleiben ehrlich: Wir erfinden keine Erfahrung oder Zertifikate. Wir formulieren nur um / sortieren um – basierend auf deinem hochgeladenen CV + Profil.",
        pipelineTitle: "Pipeline-Status",

        tailoredTitle: "Tailored CV",
        outHint: "Generiere einen CV, um Preview und ATS Match zu sehen.",
        kpiAts: "ATS Match",
        atsHint: "Berechnet aus Keyword-Abdeckung (used vs missing).",
        kpiUsed: "Keywords gefunden",
        kpiUsedHint: "Im CV gefunden.",
        kpiMissing: "Keywords fehlen",
        kpiMissingHint: "Klicke ein fehlendes Keyword, um es (ehrlich) einzufügen.",
        tabPreview: "Preview",
        tabText: "Text",
        copy: "Kopieren",
        download: "Download .txt",
        print: "Drucken / PDF",

        atsKwTitle: "ATS Keywords",
        undo: "Undo",
        reset: "Reset",
        copyMissing: "Fehlende kopieren",
        atsKwHint: "Diese Keywords kommen aus der Jobbeschreibung. Klicke ein fehlendes Keyword, um es (ehrlich) einzufügen und dein ATS Match zu verbessern.",
        usedLbl: "Used",
        missingLbl: "Missing",
        debugTitle: "Debug Details",

        // Keyword modal
        kwH: "Add keyword",
        kwSub: "Add missing keywords — only if it's truly accurate for you.",
        close: "Schließen",
        kwTruthLbl: "I confirm this keyword is true for me.",
        kwTruthNote: "We never invent experience. If it's not true, don’t add it.",
        kwWhereLbl: "Where should it appear?",
        kwWhereNote: "Skills is usually the safest option for ATS without adding new claims.",
        kwLangLbl: "Language",
        kwLangNote: "Auto passt zur Sprache deines CV. Wähle Deutsch, wenn dein CV auf Deutsch ist.",
        kwModeLbl: "Insertion mode",
        kwModeAi: "AI rewrite",
        kwModeQuick: "Quick (no AI)",
        kwModeNote: "KI integriert das Keyword natürlich. Falls dein Backend keinen KI-Endpunkt hat, nutzen wir automatisch Smart-Templates.",
        kwSkillsGroupLbl: "Which skill area?",
        kwSkillsGroupNote: "We add the keyword with clean casing and consistent style.",
        kwExpRoleLbl: "Which role?",
        kwExpHowLbl: "How to insert?",
        kwExpHowNote: "Rewriting is most natural and stays close to your real statements.",
        kwExpBulletLbl: "Which bullet?",
        kwNoteLbl: "Short note (important for new bullet)",
        kwNoteHelp: "Beispiel: „Kundenworkshops moderiert“, „OKRs eingeführt“, „SQL-Reports gebaut“. Damit bleibt es 100% wahrheitsgemäß.",
        kwPreviewLbl: "Preview",
        kwPreviewNote: "You can always use Undo/Reset.",
        kwCancel: "Cancel",
        kwApply: "Apply",

        // errors
        pickJob: "Bitte wähle zuerst einen Job.",
        needCv: "Bitte generiere zuerst einen CV.",
        truthRequired: "Bitte bestätige, dass das Keyword für dich zutrifft.",
        needDoc: "Für diese Aktion brauchen wir die strukturierte CV-Ansicht (Preview). Bitte generiere den CV erneut.",
        noteRequired: "Bitte gib einen kurzen Hinweis, wie du das Keyword wirklich angewendet hast (für einen neuen Bullet).",
        aiFallback: "KI-Endpunkt nicht verfügbar — Smart-Template wurde verwendet.",
        added: "Eingefügt ✓",
        copied: "Kopiert ✓"
      },
      en: {
        subTitle: "Paste a job description and tailor your uploaded CV with ATS-safe formatting.",
        setupTitle: "Setup",
        jobSourceLbl: "Job source",
        sourceJobs: "From my Jobs",
        sourcePaste: "Paste description",
        jobSourceHint: "Use a saved job from your queue, or paste any job description.",
        pasteJobLbl: "Pasted job (not saved)",
        pasteDescLbl: "Job description",
        pasteHint: "Tip: include Responsibilities + Requirements + Tech stack. Don’t paste confidential info.",
        pasteTitlePh: "Job title (optional)",
        pasteCompanyPh: "Company (optional)",
        pasteApplyPh: "Apply link (optional)",
        pasteLangAuto: "Language: Auto",
        pasteLangEn: "Language: English",
        pasteLangDe: "Language: German",
        pasteTooShort: "Please paste a longer job description (at least 200 characters recommended).",
        pasteTooLong: "Job description is too long. Please shorten it (max 20,000 characters).",
        pasteNotSupported: "Your backend does not support tailoring from pasted job descriptions yet. Implement /me/cv/tailor_from_text in your Worker.",
        jobToTailorLbl: "Job to tailor",
        openJobsBtn: "Open Jobs",
        btnViewDesc: "View description",
        btnCopyDesc: "Copy description",
        templateLbl: "Template",
        atsHintLine: "ATS-safe formatting = simple headings, no tables/columns, easy-to-parse structure.",
        tailorStrengthLbl: "Tailoring strength",
        light: "Light",
        balanced: "Balanced",
        aggressive: "Aggressive",
        gen: "Generate tailored CV",
        genAgain: "Generate again",
        stepsTitle: "How it works",
        stepsIntro: "This is what happens when you click “Generate”:",
        s1: "Extract job keywords",
        s2: "Align summary & bullets",
        s3: "Keep ATS-safe structure",
        s4: "Compute ATS match",
        s5: "Prepare preview & export",
        truthHint: "We stay truthful: we never invent experience or certifications. We only rephrase / reorder based on your uploaded CV + profile.",
        pipelineTitle: "Pipeline status",

        tailoredTitle: "Tailored CV",
        outHint: "Generate a CV to see preview and ATS match.",
        kpiAts: "ATS match",
        atsHint: "Calculated from keyword coverage (used vs missing).",
        kpiUsed: "Keywords used",
        kpiUsedHint: "Found in your tailored CV.",
        kpiMissing: "Keywords missing",
        kpiMissingHint: "Click a missing keyword to add it (truthfully).",
        tabPreview: "Preview",
        tabText: "Text",
        copy: "Copy",
        download: "Download .txt",
        print: "Print / PDF",

        atsKwTitle: "ATS keywords",
        undo: "Undo",
        reset: "Reset",
        copyMissing: "Copy missing",
        atsKwHint: "These keywords are extracted from the job description. Click a missing keyword to add it to your CV (truthfully) and improve your ATS match.",
        usedLbl: "Used",
        missingLbl: "Missing",
        debugTitle: "Debug details",

        kwH: "Add keyword",
        kwSub: "Add missing keywords — only if they are truly accurate.",
        close: "Close",
        kwTruthLbl: "I confirm this keyword is true for me.",
        kwTruthNote: "We don’t invent experience. If it’s not true, don’t add it.",
        kwWhereLbl: "Where should it appear?",
        kwWhereNote: "Skills is usually the safest ATS option without creating new claims.",
        kwLangLbl: "Language",
        kwLangNote: "Auto matches your CV language. Choose German if your CV is in German.",
        kwModeLbl: "Insert mode",
        kwModeAi: "AI wording",
        kwModeQuick: "Quick (no AI)",
        kwModeNote: "AI tries to integrate the keyword naturally. If your backend has no AI endpoint, we automatically fall back to smart templates.",
        kwSkillsGroupLbl: "Which skill area?",
        kwSkillsGroupNote: "We add the keyword in consistent casing and style.",
        kwExpRoleLbl: "Which role?",
        kwExpHowLbl: "How to insert?",
        kwExpHowNote: "Rewriting is most natural and stays close to your real statements.",
        kwExpBulletLbl: "Which bullet?",
        kwNoteLbl: "Short note (important for new bullet)",
        kwNoteHelp: "Example: “Facilitated client workshops”, “Implemented OKRs”, “Built SQL reports”. Keeps it 100% truthful.",
        kwPreviewLbl: "Preview",
        kwPreviewNote: "You can always use Undo/Reset.",
        kwCancel: "Cancel",
        kwApply: "Apply",

        pickJob: "Pick a job first.",
        needCv: "Generate a CV first.",
        truthRequired: "Please confirm the keyword is true for you.",
        needDoc: "This action needs the structured CV view (Preview). Please generate again.",
        noteRequired: "Please add a short note describing how you actually used this keyword (for a new bullet).",
        aiFallback: "AI endpoint not available — used smart template instead.",
        added: "Applied ✓",
        copied: "Copied ✓"
      }
    };

    function guessUiLang(){
      return "en"; // Keep the interface in English
    }

    function t(key){
      return (I18N[uiLang] && I18N[uiLang][key]) || (I18N.en[key]) || key;
    }

    function applyUiTexts(){
      uiLang = guessUiLang();
      // top
      $("subTitle").textContent = t("subTitle");
      $("setupTitle").textContent = t("setupTitle");

      // CV Studio: top actions
      try{
        const newLbl = (uiLang==="de") ? "Neuer CV" : "New CV";
        $("btnNewCv") && ($("btnNewCv").textContent = newLbl);
        $("btnNewCv") && ($("btnNewCv").title = (uiLang==="de") ? "Neuen Tailoring-Flow starten" : "Start a new tailoring flow");
      }catch(_){}

      // Step 1 chooser cards (Gate)
      try{
        if(uiLang==="de"){
          $("gatePickQueueTitle") && ($("gatePickQueueTitle").textContent = "Aus Jobs");
          $("gatePickQueueDesc") && ($("gatePickQueueDesc").textContent = "Wähle einen passenden Job aus deiner Jobs-Liste / Queue.");
          $("gatePickQueueHint") && ($("gatePickQueueHint").textContent = "Empfohlen, wenn du schon Jobs gespeichert hast.");
          $("gatePickQueueTag") && ($("gatePickQueueTag").textContent = "Empfohlen");

          $("gatePickPasteTitle") && ($("gatePickPasteTitle").textContent = "Beschreibung einfügen");
          $("gatePickPasteDesc") && ($("gatePickPasteDesc").textContent = "Füge eine beliebige Stellenbeschreibung (z.B. LinkedIn oder Website) ein.");
          $("gatePickPasteHint") && ($("gatePickPasteHint").textContent = "Tipp: Aufgaben + Anforderungen + Tech-Stack einfügen.");
          $("gatePickPasteTag") && ($("gatePickPasteTag").textContent = "Schnell");
        }
      }catch(_){}

      // Gate back button (visible in Step 2 of the gate)
      try{
        const backLbl = (uiLang==="de") ? "← Zurück" : "← Back";
        $("gateBackBtn") && ($("gateBackBtn").textContent = backLbl);
      }catch(_){}



      // Job source (queue vs paste)
      $("jobSourceLbl").textContent = t("jobSourceLbl");
      $("srcQueue").textContent = t("sourceJobs");
      $("srcPaste").textContent = t("sourcePaste");
      $("jobSourceHint").textContent = t("jobSourceHint");

      $("pasteJobLbl").textContent = t("pasteJobLbl");
      $("pasteDescLbl").textContent = t("pasteDescLbl");
      $("pasteHint").textContent = t("pasteHint");
      $("pasteTitle").setAttribute("placeholder", t("pasteTitlePh"));
      $("pasteCompany").setAttribute("placeholder", t("pasteCompanyPh"));
      $("pasteApply").setAttribute("placeholder", t("pasteApplyPh"));

      const langSel = $("pasteLangHint");
      if(langSel && langSel.options && langSel.options.length >= 3){
        langSel.options[0].textContent = t("pasteLangAuto");
        langSel.options[1].textContent = t("pasteLangEn");
        langSel.options[2].textContent = t("pasteLangDe");
      }

      $("jobToTailorLbl").textContent = t("jobToTailorLbl");
      $("openJobsBtn").textContent = t("openJobsBtn");
      $("btnViewDesc").textContent = t("btnViewDesc");
      $("btnCopyDesc").textContent = t("btnCopyDesc");
      $("templateLbl").textContent = t("templateLbl");
      $("atsHintLine").textContent = t("atsHintLine");
      $("tailorStrengthLbl").textContent = t("tailorStrengthLbl");
      $("pillLight").textContent = t("light");
      $("pillBalanced").textContent = t("balanced");
      $("pillAggressive").textContent = t("aggressive");
      $("btnGenerate").textContent = t("gen");
      $("btnGenerateAgain").textContent = t("genAgain");

      $("stepsTitle").textContent = t("stepsTitle");
      $("stepsIntro").textContent = t("stepsIntro");
      $("s1").textContent = t("s1");
      $("s2").textContent = t("s2");
      $("s3").textContent = t("s3");
      $("s4").textContent = t("s4");
      $("s5").textContent = t("s5");
      $("truthHint").textContent = t("truthHint");
      $("pipelineTitle").textContent = t("pipelineTitle");

      $("tailoredTitle").textContent = t("tailoredTitle");
      // outHint is dynamic, leave default value for now
      $("kpiAts").textContent = t("kpiAts");
      $("atsHint").textContent = t("atsHint");
      $("kpiUsed").textContent = t("kpiUsed");
      $("kpiUsedHint").textContent = t("kpiUsedHint");
      $("kpiMissing").textContent = t("kpiMissing");
      $("kpiMissingHint").textContent = t("kpiMissingHint");

      $("tabPreview").textContent = t("tabPreview");
      $("tabText").textContent = t("tabText");
      $("btnCopy").textContent = t("copy");
      $("btnDownload").textContent = t("download");
      $("btnPrint").textContent = t("print");

      $("atsKwTitle").textContent = t("atsKwTitle");
      $("btnUndoEdit").textContent = t("undo");
      $("btnResetEdits").textContent = t("reset");
      $("btnCopyMissing").textContent = t("copyMissing");
      $("atsKwHint").textContent = t("atsKwHint");
      $("usedLbl").textContent = t("usedLbl");
      $("missingLbl").textContent = t("missingLbl");
      $("debugTitle").textContent = t("debugTitle");

      // Keyword modal
      $("kwH").textContent = t("kwH");
      $("kwSub").textContent = t("kwSub");
      $("kwClose").textContent = t("close");
      $("kwTruthLbl").textContent = t("kwTruthLbl");
      $("kwTruthNote").textContent = t("kwTruthNote");
      $("kwWhereLbl").textContent = t("kwWhereLbl");
      $("kwWhereNote").textContent = t("kwWhereNote");
      $("kwLangLbl").textContent = t("kwLangLbl");
      $("kwLangNote").textContent = t("kwLangNote");
      $("kwModeLbl").textContent = t("kwModeLbl");
      $("kwModeAi").textContent = t("kwModeAi");
      $("kwModeQuick").textContent = t("kwModeQuick");
      $("kwModeNote").textContent = t("kwModeNote");
      $("kwSkillsGroupLbl").textContent = t("kwSkillsGroupLbl");
      $("kwSkillsGroupNote").textContent = t("kwSkillsGroupNote");
      $("kwExpRoleLbl").textContent = t("kwExpRoleLbl");
      $("kwExpHowLbl").textContent = t("kwExpHowLbl");
      $("kwExpHowNote").textContent = t("kwExpHowNote");
      $("kwExpBulletLbl").textContent = t("kwExpBulletLbl");
      $("kwNoteLbl").textContent = t("kwNoteLbl");
      $("kwNoteHelp").textContent = t("kwNoteHelp");
      $("kwPreviewLbl").textContent = t("kwPreviewLbl");
      $("kwPreviewNote").textContent = t("kwPreviewNote");
      $("kwCancel").textContent = t("kwCancel");
      $("kwApply").textContent = t("kwApply");
    }

    /* -------------------------
       Helpers
       ------------------------- */
    function showError(msg){ H.showTopError("errorTop", msg || ""); }
    function setBadge(id, cls, txt){
      H.setBadge(id, cls, txt);
      // Mirror auth status into the top bar (so it stays visible when Setup is collapsed)
      if(id === "authBadge") H.setBadge("authBadgeTop", cls, txt);
    }
    function setText(id, txt){ const el = $(id); if (el) el.textContent = (txt == null) ? "" : String(txt); }

/* -------------------------
   Focus mode: collapsible Setup panel + “How it works” modal
   ------------------------- */
function setSetupCollapsed(collapsed, opts = {}){
  const persist = (opts.persist !== false);
  const scroll = (opts.scroll !== false);

  setupCollapsed = !!collapsed;
  const studio = document.querySelector(".studio");
  if(studio) studio.classList.toggle("setupCollapsed", setupCollapsed);

  if(persist){
    try{ localStorage.setItem("cvstudio_setup_collapsed", setupCollapsed ? "1" : "0"); }catch(_){}
  }

  if(scroll && setupCollapsed){
    try{ document.querySelector(".studioCanvas")?.scrollIntoView({ behavior:"smooth", block:"start" }); }catch(_){}
  }
}

function maybeAutoCollapseAfterPaste(){
  if(jobSource !== "paste") return;
  if(setupUserToggled) return;
  if(setupAutoCollapsedOnce) return;

  const desc = getPasteDesc();
  if(desc.length < 260) return;

  // Collapse only after the user stopped typing for a moment (prevents jumpiness)
  window.clearTimeout(maybeAutoCollapseAfterPaste._t);
  maybeAutoCollapseAfterPaste._t = window.setTimeout(() => {
    if(jobSource !== "paste") return;
    if(setupUserToggled) return;
    if(setupAutoCollapsedOnce) return;
    if(getPasteDesc().length >= 260){
      setupAutoCollapsedOnce = true;
      // Leaving Step 1 gate (if active) opens the full studio view
      exitGate();

      setSetupCollapsed(true, { persist:false });
    }
  }, 900);
}

function openGenModal(auto = false){
  genModalAuto = !!auto;

  // Ensure labels are localized (light touch; no refactor)
  setText("genVizLabel", uiLang==="de" ? "Vorschau" : "Merge preview");
  setText("genVizJdTitle", uiLang==="de" ? "Jobbeschreibung" : "Job description");
  setText("genVizCvTitle", uiLang==="de" ? "Dein CV" : "Your CV");
  setText("genVizOutTitle", uiLang==="de" ? "Angepasster CV" : "Tailored CV");

  const jm = getActiveJobMeta();
  const title = (jm && jm.title) ? String(jm.title).trim() : "";
  const company = (jm && jm.company_name) ? String(jm.company_name).trim() : "";

  const label = title
    ? (title + (company ? (" · " + company) : ""))
    : "—";

  setText("genJobBadge", label);

  // Show the job title at the top of the “Tailored CV” card
  setText("genVizJobTitle", title || "—");
  setText("genVizJobMeta", company || "");

  // Sync the little animation to current state (idle/running/done/error)
  try{ setGenVizState(auto ? "running" : (genStepsState || "idle")); }catch(_){ }

  H.showModal("genModal");
}


function closeGenModal(){
  genModalAuto = false;
  H.hideModal("genModal");
}

    function qs(name){
      try{ return new URL(window.location.href).searchParams.get(name); }
      catch{ return null; }
    }

    function joinNonEmpty(arr, sep){
      return (arr || []).map(x => String(x || "").trim()).filter(Boolean).join(sep);
    }
    function asStringArr(arr, max=999){
      if(!Array.isArray(arr)) return [];
      return arr.map(x => String(x || "").trim()).filter(Boolean).slice(0, max);
    }

    // Small, stable hash for caching pasted descriptions in localStorage
    function fnv1a(str){
      let h = 0x811c9dc5;
      const s = String(str || "");
      for(let i=0;i<s.length;i++){
        h ^= s.charCodeAt(i);
        h = (h + ((h<<1) + (h<<4) + (h<<7) + (h<<8) + (h<<24))) >>> 0;
      }
      return ("00000000" + h.toString(16)).slice(-8);
    }

    
/* -------------------------
   Step 1 Gate (entry flow)
   ------------------------- */

/* -------------------------
   Incoming from Jobs (auto-start)
   ------------------------- */
let incomingJobId = "";
let autoStartTimer = null;
let autoStartArmed = false;

function isIncomingFromJobs(){
  return !!String(incomingJobId || "").trim();
}

function setFromJobsUi(){
  document.body.classList.toggle("fromJobsLink", isIncomingFromJobs());
}

function showAutoStartBar(show, msg){
  const bar = $("autoStartBar");
  if(!bar) return;
  bar.style.display = show ? "" : "none";
  if(msg){
    const d = $("autoStartDesc");
    if(d) d.textContent = String(msg);
  }
}

function clearAutoStartTimer(){
  if(autoStartTimer){
    try{ clearTimeout(autoStartTimer); }catch(_){}
    autoStartTimer = null;
  }
  autoStartArmed = false;
}

function cancelAutoStart(userInitiated = true){
  clearAutoStartTimer();
  showAutoStartBar(false);
  if(userInitiated){
    try{ window.JobMeJobShared?.toast?.("Tip hidden. You can tweak settings and click Generate.", { kind:"warn", title:"CV Studio" }); }catch(_){}
  }
}


/* -------------------------
   Guided settings glow (Jobs → CV Studio)
   - Highlights Template + Tailoring strength until user clicks Generate
   ------------------------- */
let guidedSettingsGlowOn = false;

function setGuidedSettingsGlow(on){
  guidedSettingsGlowOn = !!on;

  // Template: highlight the entire row (select + ATS? button)
  let tplRow = null;
  try{
    const sel = $("tplSelect");
    tplRow = sel && sel.closest ? sel.closest(".row") : null;
  }catch(_){}

  // Strength: highlight the whole strength wrapper
  let strengthBox = null;
  try{
    strengthBox = document.querySelector(".strengthWrap");
  }catch(_){}

  const els = [tplRow, strengthBox];
  for(const el of els){
    if(!el) continue;
    el.classList.toggle("guidedGlow", guidedSettingsGlowOn);
    el.classList.toggle("guidedPulse", guidedSettingsGlowOn);
  }
}

function armAutoStartFromJobs(){
  if(!isIncomingFromJobs()) return;

  // Only meaningful in queue mode
  if(jobSource !== "queue") return;
  if(!selectedJob) return;

  // Safety: if the job_id isn't in your queue, don't proceed (avoid tailoring the wrong job)
  if(String(selectedJob?.id || "") !== String(incomingJobId || "")){
    showAutoStartBar(false);
    try{
      window.JobMeJobShared?.toast?.(
        uiLang==="de"
          ? "Dieser Job ist nicht in deiner Queue. Öffne Jobs und lade (fetch) erneut."
          : "This job isn’t in your queue. Open Jobs and fetch again.",
        { kind:"warn", title:"CV Studio" }
      );
    }catch(_){}
    return;
  }

  // IMPORTANT UX:
  // Coming from Jobs should *stop* at the tailoring settings so the user can review Template + Strength.
  // No auto-start.
  try{ setSetupCollapsed(false, { persist:false, scroll:false }); }catch(_){}
  setupUserToggled = true;
  try{ $("settingsDetails").open = true; }catch(_){}

  showAutoStartBar(true, uiLang==="de"
    ? "Vorlage & Stärke auswählen – dann „Generate tailored CV“ klicken."
    : "Choose template & strength — then click “Generate tailored CV”."
  );

  try{ setGuidedSettingsGlow(true); }catch(_){ }


  // No timer, no auto-run.
}

let gateActive = false;

let gateView = "choose"; // "choose" | "form"

function setGateView(view){
  gateView = (view === "form") ? "form" : "choose";

  // Helper class so CSS can handle most visibility rules
  document.body.classList.toggle("cvGateForm", gateActive && gateView === "form");

  // Explicit toggles (safe if elements are missing)
  const chooser = $("gateChooser");
  const formWrap = $("gateFormWrap");
  const backRow = $("gateBackRow");
  const backBadge = $("gateBackBadge");

  if(chooser) chooser.style.display = (gateActive && gateView === "choose") ? "" : "none";
  if(formWrap) formWrap.style.display = (!gateActive || gateView === "form") ? "" : "none";
  if(backRow) backRow.style.display = (gateActive && gateView === "form") ? "flex" : "none";

  // Update step header copy (keeps the flow obvious)
  const st = $("setupTitle");
  const title = $("gateStepTitle");
  const hint = $("gateStepHint");
  const badge = $("gateStepBadge");

  if(!gateActive){
    if(st) st.textContent = t("setupTitle") || "Setup";
    return;
  }

  if(gateView === "choose"){
    // The stepper already communicates the step number — keep this header clean.
    if(st) st.textContent = t("setupTitle") || "Setup";
    if(title) title.textContent = (uiLang==="de")
      ? "Job-Quelle wählen"
      : "Choose your job source";
    if(hint) hint.textContent = (uiLang==="de")
      ? "Wähle eine Option. Danach ergänzt du die Details und startest das Tailoring."
      : "Choose one option. Next you’ll add the details and start tailoring.";
    try{ renderGateStepper(1); }catch(_){ }
    return;
  }

  // gateView === "form"
  if(st) st.textContent = t("setupTitle") || "Setup";
  if(title) title.textContent = (uiLang==="de")
    ? "Job-Details hinzufügen"
    : "Add job details";

  // Keep "Settings (optional)" open by default in Step 2 (both sources)
  try{ $("settingsDetails").open = true; }catch(_){ }

  if(hint){
    hint.textContent = (jobSource === "paste")
      ? ((uiLang==="de")
          ? "Füge die Stellenbeschreibung ein (am besten das komplette Posting) und starte dann das Tailoring."
          : "Paste the job description (full posting is best), then start tailoring.")
      : ((uiLang==="de")
          ? "Wähle einen Job aus deiner Queue und starte dann das Tailoring."
          : "Pick a job from your queue, then start tailoring.");
  }
  try{ renderGateStepper(2); }catch(_){ }
  try{ updateCtaHint(); }catch(_){ }
}

  function renderGateStepper(step){
    const wrap = $("gateStepper");
    if(!wrap) return;

    const l1 = $("stepperLbl1");
    const l2 = $("stepperLbl2");
    const l3 = $("stepperLbl3");
    if(l1) l1.textContent = (uiLang==="de") ? "Quelle" : "Source";
    if(l2) l2.textContent = (uiLang==="de") ? "Details" : "Details";
    if(l3) l3.textContent = (uiLang==="de") ? "Studio" : "Studio";

    const s1 = $("stepper1");
    const s2 = $("stepper2");
    const s3 = $("stepper3");
    const l12 = $("stepLine12");
    const l23 = $("stepLine23");

    const clear = (el) => { if(el){ el.classList.remove("active"); el.classList.remove("done"); } };
    const clearLine = (el) => { if(el){ el.classList.remove("done"); } };
    clear(s1); clear(s2); clear(s3);
    clearLine(l12); clearLine(l23);

    const st = Number(step) || 1;
    if(st <= 1){
      if(s1) s1.classList.add("active");
      return;
    }
    if(st === 2){
      if(s1) s1.classList.add("done");
      if(l12) l12.classList.add("done");
      if(s2) s2.classList.add("active");
      return;
    }
    // step 3
    if(s1) s1.classList.add("done");
    if(l12) l12.classList.add("done");
    if(s2) s2.classList.add("done");
    if(l23) l23.classList.add("done");
    if(s3) s3.classList.add("active");
  }




function cameFromJobsPage(){
  const urlJobId = String(qs("job_id") || "").trim();
  if(urlJobId) return true;

  try{
    const ref = String(document.referrer || "");
    if(ref.includes("/jobs.html")) return true;
  }catch(_){}

  return false;
}

function shouldShowGate(){
  if(STANDALONE_MODE) return false;
  if(cameFromJobsPage()) return false;
  try{
    if(sessionStorage.getItem("cvstudio_started") === "1") return false;
  }catch(_){}
  return true;
}

function applyStandaloneShell(){
  if(!STANDALONE_MODE) return;
  try{ document.body.classList.add("cvstudioStandalone"); }catch(_){}
  try{
    const navActivity = $("navActivity");
    if(navActivity) navActivity.style.display = "none";
  }catch(_){}
  try{
    const chooser = $("gateChooser");
    if(chooser) chooser.style.display = "none";
  }catch(_){}
  try{
    const intro = $("gateIntro");
    if(intro) intro.style.display = "none";
  }catch(_){}
  try{
    const sourcePills = $("sourcePills");
    if(sourcePills) sourcePills.style.display = "none";
  }catch(_){}
  try{
    const queueBox = $("queueBox");
    if(queueBox) queueBox.style.display = "none";
  }catch(_){}
  try{
    const gateBackRow = $("gateBackRow");
    if(gateBackRow) gateBackRow.style.display = "none";
  }catch(_){}
  try{
    const autoStartBar = $("autoStartBar");
    if(autoStartBar) autoStartBar.style.display = "none";
  }catch(_){}
  try{
    const sourceHint = $("jobSourceHint");
      if(sourceHint) sourceHint.textContent = uiLang==="de"
      ? "Fuege die vollstaendige Stellenbeschreibung ein und generiere danach deinen Tailored CV."
      : "Paste the full job description and generate your tailored CV.";
  }catch(_){}
  try{
    const sourceLabel = $("jobSourceLbl");
    if(sourceLabel) sourceLabel.textContent = uiLang==="de" ? "Jobbeschreibung" : "Job description";
  }catch(_){}
}

function setGateActive(on){
  gateActive = !!on;

  document.body.classList.toggle("cvGate", gateActive);
  if(!gateActive){
    document.body.classList.remove("cvGateForm");
  }

  try{ $("gateIntro").style.display = gateActive ? "" : "none"; }catch(_){}

  // Make sure Setup is visible in Step 1
  if(gateActive){
    setSetupCollapsed(false, { persist:false, scroll:false });
    try{ setGuidedSettingsGlow(false); }catch(_){ }
    setupUserToggled = true; // avoid auto-collapse fighting Step 1
  }

  // Make the primary action clear
  const genBtn = $("btnGenerate");
  if(genBtn){
    genBtn.textContent = gateActive ? "Start tailoring →" : "Generate tailored CV";
  }

  // Keep second button hidden to reduce confusion
  try{ $("btnGenerateAgain").style.display = "none"; }catch(_){}

  // Default gate view when entering
  if(gateActive) setGateView("choose");
  else setGateView("form");
}

function exitGate(){
  if(!gateActive) return;
  try{ sessionStorage.setItem("cvstudio_started","1"); }catch(_){}
  setGateActive(false);
  // After Step 1, open the studio in Tailor mode (calm preview)
  try{ setStudioMode("tailor"); }catch(_){ }

  // Restore normal title
  const st = $("setupTitle");
  if(st){
    st.textContent = t("setupTitle") || "Setup";
  }

  try{ if(typeof updateSourceChip === "function") updateSourceChip(); }catch(_){ }
}

function getPasteDesc(){
      return String($("pasteDesc")?.value || "").trim();
    }

    function getActiveJobMeta(){
      if(jobSource === "paste"){
        const title = String($("pasteTitle")?.value || "").trim();
        const company_name = String($("pasteCompany")?.value || "").trim();
        const apply_url = applyUrlSafe(String($("pasteApply")?.value || "").trim());
        return {
          title: title || (uiLang==="de" ? "Eingefügter Job" : "Pasted job"),
          company_name,
          apply_url
        };
      }
      return {
        title: String(selectedJob?.title || "").trim(),
        company_name: String(selectedJob?.company_name || "").trim(),
        apply_url: applyUrlSafe(selectedJob?.apply_url || "")
      };
    }

    function shortText(s, maxLen){
      const str = String(s || "");
      const n = Number(maxLen || 42);
      if(!str) return "";
      if(str.length <= n) return str;
      return str.slice(0, Math.max(0, n - 1)) + "…";
    }

    function updateSourceChip(){
      const pill = $("sourceChipPill");
      if(!pill) return;

      // In Step 1 gate the studio bar is hidden anyway
      if(gateActive){
        pill.style.display = "none";
        return;
      }

      // Determine current "context" (job or paste)
      let meta = null;
      try{ meta = getActiveJobMeta(); }catch(_){ meta = null; }

      const title = String(meta?.title || "").trim();
      const company = String(meta?.company_name || "").trim();

      // If paste mode but no real description yet, keep it hidden (avoids confusion)
      if(jobSource === "paste"){
        const d = getPasteDesc();
        if(d.length < 40 && !title){
          pill.style.display = "none";
          return;
        }
      }

      let full = title || (jobSource === "paste"
        ? (uiLang==="de" ? "Eingefügte Beschreibung" : "Pasted description")
        : (uiLang==="de" ? "Ausgewählter Job" : "Selected job")
      );

      if(company) full = full + " · " + company;

      const lbl = $("sourceChipLabel");
      if(lbl) lbl.textContent = (uiLang==="de" ? "Aktiv:" : "Using:");

      const val = $("sourceChipValue");
      if(val){
        val.textContent = shortText(full, 64);
        val.title = full;
      }

      pill.style.display = "";
    }

function openGateForNewCv(){
  if(STANDALONE_MODE){
    try{ cancelAutoStart(false); }catch(_){ }
    try{ setGateActive(false); }catch(_){ }
    try{ setJobSource("paste"); }catch(_){ jobSource = "paste"; }
    try{
      $("pasteTitle").value = "";
      $("pasteCompany").value = "";
      $("pasteApply").value = "";
      $("pasteLangHint").value = "auto";
      $("pasteDesc").value = "";
      savePasteDraft();
      updatePasteQuality();
    }catch(_){}
    try{
      selectedJob = null;
      selectedDesc = "";
      selectedApplyUrl = "";
      pendingExtensionImport = null;
      lastCvText = "";
      lastCvDoc = null;
      lastLang = "en";
      lastUsed = [];
      lastMissing = [];
      atsKeywordsAll = [];
      lastDebug = {};
      baseSnapshot = null;
      historyStack = [];
      setText("jobMeta", "");
      setText("jobHint", uiLang==="de" ? "Fuege eine Stellenbeschreibung ein." : "Paste a job description to start.");
      renderKeywords();
      setTabs("preview");
      markSteps("idle");
      setOutputEnabled(false);
      updateUndoResetButtons();
    }catch(_){}
    try{
      $("cvPreview").innerHTML = `<div class="hint">${uiLang==="de" ? "Noch kein CV generiert." : "No CV generated yet."}</div>`;
      $("cvText").value = "";
      setBadge("outStatus", "warn", uiLang==="de" ? "Nicht generiert" : "Not generated");
      setText("outHint", uiLang==="de" ? "Fuege eine Stellenbeschreibung ein und generiere dann deinen CV." : "Paste a job description, then generate your CV.");
      setText("debugBox", "—");
      $("pipeBox").textContent = "Generate a CV to see pipeline details.";
    }catch(_){}
    try{
      window.scrollTo({ top: 0, behavior: "smooth" });
      $("pasteDesc")?.focus();
    }catch(_){}
    return;
  }
  try{ cancelAutoStart(false); }catch(_){ }

      // Opens the Step 1 chooser (clean start)
      try{
        // If they reload while here, keep them in Step 1
        sessionStorage.removeItem("cvstudio_started");
      }catch(_){}

      // Clear job_id from URL (no reload) so “New CV” is a clean start
      try{
        const u = new URL(window.location.href);
        if(u.searchParams.has("job_id")){
          u.searchParams.delete("job_id");
          history.replaceState({}, "", u.toString());
        try{ incomingJobId = ""; setFromJobsUi(); }catch(_){ }

        }
      }catch(_){}

      try{
        setGateActive(true);
        setGateView("choose");
      }catch(_){
        try{ document.body.classList.add("cvGate"); }catch(__){}
      }

      try{
        window.scrollTo({ top: 0, behavior: "smooth" });
      }catch(_){
        try{ window.scrollTo(0,0); }catch(__){}
      }
    }

    // Optional: a "change" entrypoint that skips the chooser and jumps straight to Step 2
    function openGateForChange(){
      try{
        sessionStorage.removeItem("cvstudio_started");
      }catch(_){}

      try{
        setGateActive(true);
        setGateView("form");
      }catch(_){
        try{ document.body.classList.add("cvGate"); }catch(__){}
      }

      setTimeout(() => {
        try{
          if(jobSource === "paste") $("pasteDesc")?.focus();
          else $("jobSelect")?.focus();
        }catch(_){}
      }, 60);

      try{
        window.scrollTo({ top: 0, behavior: "smooth" });
      }catch(_){
        try{ window.scrollTo(0,0); }catch(__){}
      }
    }

function loadJobSource(){
      if(STANDALONE_MODE){
        jobSource = "paste";
        return;
      }
      try{
        const v = String(localStorage.getItem("cvstudio_job_source") || "").trim();
        jobSource = (v === "paste") ? "paste" : "queue";
      }catch(_){
        jobSource = "queue";
      }
    }

    function loadPasteDraft(){
      try{
        const raw = localStorage.getItem("cvstudio_paste_draft");
        if(!raw) return;
        const obj = JSON.parse(raw);
        if(!obj) return;
        pasteDraft = {
          title: String(obj.title||""),
          company: String(obj.company||""),
          apply: String(obj.apply||""),
          lang_hint: String(obj.lang_hint||"auto"),
          desc: String(obj.desc||"")
        };
      }catch(_){}
    }

    function consumeExtensionImport(){
      try{
        const raw = localStorage.getItem(EXT_IMPORT_KEY);
        if(!raw) return null;
        localStorage.removeItem(EXT_IMPORT_KEY);

        const obj = JSON.parse(raw);
        if(!obj || typeof obj !== "object") return null;

        const desc = String(obj.description || obj.job_description || "").trim().slice(0, EXT_IMPORT_MAX_DESC);
        if(!desc) return null;

        return {
          title: String(obj.title || obj.job_title || "").trim(),
          company: String(obj.company || obj.company_name || "").trim(),
          apply: String(obj.apply_url || obj.url || "").trim(),
          lang_hint: String(obj.language_hint || obj.lang_hint || "auto").trim().toLowerCase() || "auto",
          desc,
          source_host: String(obj.source_host || "").trim(),
          source: String(obj.source || "chrome_extension").trim()
        };
      }catch(_){
        try{ localStorage.removeItem(EXT_IMPORT_KEY); }catch(__){}
        return null;
      }
    }

    function applyExtensionImportToDraft(data){
      const imp = data && typeof data === "object" ? data : null;
      if(!imp || !String(imp.desc || "").trim()) return false;

      pendingExtensionImport = imp;
      pasteDraft = {
        title: String(imp.title || ""),
        company: String(imp.company || ""),
        apply: String(imp.apply || ""),
        lang_hint: String(imp.lang_hint || "auto"),
        desc: String(imp.desc || "")
      };
      jobSource = "paste";

      try{ localStorage.setItem("cvstudio_job_source", "paste"); }catch(_){}
      try{ localStorage.setItem("cvstudio_paste_draft", JSON.stringify({ ...pasteDraft, at: Date.now(), source: imp.source || "chrome_extension" })); }catch(_){}
      return true;
    }

    function savePasteDraft(){
      try{
        pasteDraft = {
          title: String($("pasteTitle")?.value || ""),
          company: String($("pasteCompany")?.value || ""),
          apply: String($("pasteApply")?.value || ""),
          lang_hint: String($("pasteLangHint")?.value || "auto"),
          desc: String($("pasteDesc")?.value || "")
        };
        localStorage.setItem("cvstudio_paste_draft", JSON.stringify({ ...pasteDraft, at: Date.now() }));
      }catch(_){}
    }

    function applyPasteDraftToInputs(){
      try{
        $("pasteTitle").value = pasteDraft.title || "";
        $("pasteCompany").value = pasteDraft.company || "";
        $("pasteApply").value = pasteDraft.apply || "";
        $("pasteLangHint").value = pasteDraft.lang_hint || "auto";
        $("pasteDesc").value = pasteDraft.desc || "";
      }catch(_){}
    }

    function setJobSource(mode){
      jobSource = (mode === "paste") ? "paste" : "queue";
      try{ localStorage.setItem("cvstudio_job_source", jobSource); }catch(_){}

      $("srcQueue")?.classList.toggle("active", jobSource === "queue");
      $("srcPaste")?.classList.toggle("active", jobSource === "paste");

      $("queueBox").style.display = jobSource === "queue" ? "" : "none";
      $("pasteBox").style.display = jobSource === "paste" ? "" : "none";

      refreshModeUi();

      if(jobSource === "queue"){
        // refresh selection UI
        try{ onJobChange(); }catch(_){}
      }else{
        // update quality and enablement
        try{ updatePasteQuality(); }catch(_){}
      }

      try{ updateSourceChip(); }catch(_){}

      // In the guided Step 2 flow, keep Settings visible (it is a key feature)
      try{ if(document.body.classList.contains("cvGateForm")) $("settingsDetails").open = true; }catch(_){ }

    }


    // ------------------------------------------------------------
    // Guided attention: highlight the required field when CTA is disabled
    // (Best practice: helps users immediately see what to do next.)
    // Only active in Step 2 (gate form).
    // ------------------------------------------------------------
    function clearAttention(){
      try{ $("jobSelect") && $("jobSelect").classList.remove("needAttention"); }catch(_){}
      try{ $("openJobsBtn") && $("openJobsBtn").classList.remove("needAttention"); }catch(_){}
      try{ $("pasteDesc") && $("pasteDesc").classList.remove("needAttention"); }catch(_){}
    }

    function updateAttention(){
      clearAttention();

      // Only show this helper in the guided Step 2 screen
      if(!gateActive || gateView !== "form") return;

      if(jobSource === "queue"){
        if(!selectedJob){
          if(jobs && jobs.length === 0){
            try{ $("openJobsBtn").classList.add("needAttention"); }catch(_){}
          }else{
            try{ $("jobSelect").classList.add("needAttention"); }catch(_){}
          }
        }
        return;
      }

      // paste
      const len = getPasteDesc().length;
      if(len < 120){
        try{ $("pasteDesc").classList.add("needAttention"); }catch(_){}
      }
    }

    function refreshModeUi(){
      if(jobSource === "queue"){
        const ok = !!selectedJob;
        $("btnGenerate").disabled = !ok;
        $("btnGenerateAgain").disabled = !ok;
        $("btnViewDesc").disabled = !ok;
        $("btnCopyDesc").disabled = !ok;
        try{ updateCtaHint(); }catch(_){ }
        try{ updateAttention(); }catch(_){ }
        return;
      }

      // paste mode
      const desc = getPasteDesc();
      const len = desc.length;

      // allow generation at >=120 chars, recommend >=200
      const ok = len >= 120;

      $("btnGenerate").disabled = !ok;
      $("btnGenerateAgain").disabled = !ok;

      const hasAny = len > 0;
      $("btnViewDesc").disabled = !hasAny;
      $("btnCopyDesc").disabled = !hasAny;
      try{ updateCtaHint(); }catch(_){ }
      try{ updateAttention(); }catch(_){ }
    }

    function updateCtaHint(){
      const cta = $("ctaHint");
      if(!cta) return;

      // Only show this helper in the guided Step 2 screen
      if(!gateActive || gateView !== "form"){
        cta.style.display = "none";
        cta.textContent = "";
        return;
      }

      cta.style.display = "block";

      if(jobSource === "queue"){
        if(!selectedJob){
          if(jobs && jobs.length === 0){
            cta.textContent = (uiLang==="de")
              ? "Deine Job-Queue ist leer. Öffne die Jobs-Seite und lade zuerst passende Jobs."
              : "Your job queue is empty. Open the Jobs page and fetch jobs first.";
          }else{
            cta.textContent = (uiLang==="de")
              ? "Wähle zuerst einen Job aus, um „Start tailoring“ zu aktivieren."
              : "Choose a job to enable Start tailoring.";
          }
          return;
        }
        cta.textContent = (uiLang==="de")
          ? "Bereit — wähle Template & Stärke (optional) und klicke dann „Start tailoring“."
          : "Ready — review template & strength (optional), then click Start tailoring.";
        return;
      }

      // paste
      const desc = getPasteDesc();
      const len = desc.length;
      if(len < 120){
        cta.textContent = (uiLang==="de")
          ? "Füge mindestens ca. 120 Zeichen ein, um „Start tailoring“ zu aktivieren."
          : "Paste at least ~120 characters to enable Start tailoring.";
        return;
      }
      if(len < 200){
        cta.textContent = (uiLang==="de")
          ? "Du kannst starten. Für bessere Resultate: mehr Kontext (Aufgaben + Anforderungen)."
          : "You can start. For best results, include Responsibilities + Requirements.";
        return;
      }
      cta.textContent = (uiLang==="de")
        ? "Bereit — wähle Template & Stärke (optional) und klicke dann „Start tailoring“."
        : "Ready — review template & strength (optional), then click Start tailoring.";
    }

function updatePasteQuality(){
      const desc = getPasteDesc();
      const pill = $("pasteQualityPill");
      const label = $("pasteQuality");

      const len = desc.length;
      const words = desc ? desc.split(/\s+/).filter(Boolean).length : 0;
      const lines = desc ? desc.split(/\n/).length : 0;

      // heuristics (English + German)
      const hasReq = /(requirements|qualifications|what you.*bring|we (are )?looking for|must have|you should|anforderungen|qualifikation|du bringst|wir suchen|solltest)/i.test(desc);
      const hasResp = /(responsibilities|what you.*do|your role|tasks|aufgaben|deine aufgaben|verantwortlichkeiten)/i.test(desc);

      let status = "warn";
      let msg = "";

      if(len < 50){
        msg = "Paste the full job posting for best results.";
      }else if(len < 200){
        msg = `Looks short (${len} chars). Include Responsibilities + Requirements for best tailoring.`;
      }else{
        status = "good";
        msg = `Looks good: ${len} chars · ${words} words · ${lines} lines` + ((hasReq || hasResp) ? "" : " (Tip: include requirements/tasks)");
      }

      if(pill){
        pill.classList.toggle("good", status === "good");
        pill.classList.toggle("warn", status !== "good");
        pill.textContent = status === "good" ? "Good" : "Needs more";
      }
      if(label) label.textContent = msg;

      // cache key for local storage outputs (not a security hash, just a stable key)
      const tpl = String($("tplSelect")?.value || "professional").trim().toLowerCase();
      const s = (strengthValue()?.key) || "balanced";
      const langHint = String($("pasteLangHint")?.value || "auto");
      pasteCacheKey = "cvstudio_last_" + "paste_" + fnv1a(desc + "|" + tpl + "|" + s + "|" + langHint);

      refreshModeUi();
    }

    function deepCopy(obj){
      try{ return JSON.parse(JSON.stringify(obj)); }catch(_){ return null; }
    }

    function formatLoc(j){
      const parts = [];
      if (j.city) parts.push(j.city);
      if (j.region && j.region !== j.city) parts.push(j.region);
      if (j.country) parts.push(j.country);
      return parts.filter(Boolean).join(", ");
    }

    function applyUrlSafe(url){
      const u = String(url || "").trim();
      if (!u) return "";
      if (/^https?:\/\//i.test(u)) return u;
      return "https://" + u.replace(/^\/+/, "");
    }

    function isLikelyGerman(lang){
      const l = String(lang || "").toLowerCase();
      return l.startsWith("de");
    }

    /* Keyword casing + matching */
    const ACRONYMS = new Set([
      "API","APIs","SQL","AWS","GCP","AZURE","KPI","KPIs","OKR","OKRs","CRM","ERP","ETL","CI/CD","CI","CD","SaaS","B2B","B2C","GDPR","DSGVO","HR","UX","UI","QA","SEO","SEA"
    ]);

    function normalizeSpaces(s){ return String(s||"").replace(/\s+/g," ").trim(); }

    function titleCaseWord(w){
      if(!w) return w;
      const up = w.toUpperCase();
      if(ACRONYMS.has(up)) return up;
      // keep words that already contain uppercase letters or digits
      if(/[A-ZÄÖÜ]/.test(w)) return w;
      return w.charAt(0).toUpperCase() + w.slice(1);
    }

    function prettyKeyword(raw, lang){
      const k = normalizeSpaces(raw);
      if(!k) return k;

      // If it looks like an acronym, upper it
      if(k.length <= 5 && /^[a-z0-9\/\-\+]+$/.test(k) && /[a-z]/.test(k)){
        const up = k.toUpperCase();
        if(ACRONYMS.has(up)) return up;
      }

      // If mostly lowercase, apply title-ish case
      const lowerRatio = (k.match(/[a-zäöü]/g)||[]).length / Math.max(1,(k.match(/[a-zA-ZÄÖÜäöü]/g)||[]).length);
      if(lowerRatio > 0.75){
        const parts = k.split(" ").map(p => {
          // handle hyphenated
          return p.split("-").map(titleCaseWord).join("-");
        });
        return parts.join(" ");
      }
      return k;
    }

    function normForMatch(s){
      // lower, remove punctuation -> spaces, collapse
      const str = String(s||"").toLowerCase();
      try{
        return str.replace(/[^\p{L}\p{N}]+/gu, " ").trim().replace(/\s+/g, " ");
      }catch(_){
        return str.replace(/[^a-z0-9äöüß]+/g, " ").trim().replace(/\s+/g, " ");
      }
    }


    function tokenizeForScore(s){
      const n = normForMatch(s);
      return n ? n.split(" ").filter(Boolean) : [];
    }

    function scoreBulletForKeyword(bullet, keyword){
      const b = tokenizeForScore(bullet);
      const k = tokenizeForScore(keyword);
      if(!b.length || !k.length) return 0;
      const bSet = new Set(b);
      let hit = 0;
      for(const t of k){
        if(bSet.has(t)) hit += 2;
      }
      const kwNorm = normForMatch(keyword);
      const bNorm = normForMatch(bullet);
      if(kwNorm && bNorm.includes(kwNorm)) hit += 6;
      // Prefer medium-length bullets (not too short, not too long)
      const len = String(bullet||"").length;
      if(len >= 40 && len <= 140) hit += 1;
      return hit;
    }

    function pickBestBulletIndex(keyword, bullets){
      let best = 0;
      let bestScore = -1;
      bullets.forEach((b, i) => {
        const s = scoreBulletForKeyword(b, keyword);
        if(s > bestScore){
          bestScore = s;
          best = i;
        }
      });
      return { index: best, score: bestScore };
    }

    function isToolLikeKeyword(keyword){
      const k = normForMatch(keyword);
      return ["sql","excel","power bi","tableau","jira","confluence","sap","aws","gcp","azure","python","r","looker","snowflake","dbt","airflow","kpi","okr","crm"].some(x => k === x);
    }

    function pickBestRoleAndBullet(keyword){
      const exp = Array.isArray(lastCvDoc?.experience) ? lastCvDoc.experience : [];
      let best = { expIdx: 0, bulletIdx: 0, score: -1 };
      exp.forEach((e, expIdx) => {
        const bullets = asStringArr(e?.bullets, 50);
        const r = pickBestBulletIndex(keyword, bullets);
        if(r.score > best.score){
          best = { expIdx, bulletIdx: r.index, score: r.score };
        }
      });
      return best;
    }
    function keywordInText(keyword, text){
      const k = normForMatch(keyword);
      const ttxt = normForMatch(text);
      if(!k) return false;
      return ttxt.includes(k);
    }

    /* Deterministic variation (no randomness across refreshes) */
    function hashString(s){
      const str = String(s||"");
      let h = 2166136261;
      for(let i=0;i<str.length;i++){
        h ^= str.charCodeAt(i);
        h = Math.imul(h, 16777619);
      }
      return (h >>> 0);
    }
    function pick(arr, seed){
      if(!arr.length) return "";
      const i = (seed % arr.length);
      return arr[i];
    }

    function localRewriteBullet(bullet, keyword, lang){
      const b = String(bullet||"").trim();
      const kw = prettyKeyword(keyword, lang);
      if(!b) return kw;
      if(keywordInText(keyword, b) || keywordInText(kw, b)) return b;

      const de = isLikelyGerman(lang);
      const seed = hashString(keyword + "|" + b + "|" + lang);

      const phrasesDe = [
        "mit Fokus auf " + kw,
        "unter Einsatz von " + kw,
        "unter Anwendung von " + kw,
        "inklusive " + kw,
        "in Bezug auf " + kw
      ];
      const phrasesEn = [
        "with a focus on " + kw,
        "using " + kw,
        "leveraging " + kw,
        "including " + kw,
        "related to " + kw
      ];
      const phrase = pick(de ? phrasesDe : phrasesEn, seed);

      // Choose joiner
      const joinersDe = [" – ", "; ", ", "];
      const joinersEn = [" – ", "; ", ", "];
      const joiner = pick(de ? joinersDe : joinersEn, seed + 7);

      // If bullet ends with punctuation, keep
      const end = b.slice(-1);
      const base = /[.!?]$/.test(end) ? b.slice(0,-1) : b;

      return base + joiner + phrase + ".";
    }

    function localAppendKeyword(bullet, keyword, lang){
      // Append (smaller change than rewrite)
      const b = String(bullet||"").trim();
      const kw = prettyKeyword(keyword, lang);
      if(!b) return kw;
      if(keywordInText(keyword, b) || keywordInText(kw, b)) return b;

      const de = isLikelyGerman(lang);
      const seed = hashString(keyword + "|" + b + "|" + lang);

      const tailsDe = [
        "(inkl. " + kw + ")",
        "(Fokus: " + kw + ")",
        "(mit " + kw + ")"
      ];
      const tailsEn = [
        "(incl. " + kw + ")",
        "(focus: " + kw + ")",
        "(with " + kw + ")"
      ];
      const tail = pick(de ? tailsDe : tailsEn, seed);

      // If already ends with punctuation, add space then tail, else add " " then tail.
      if(/[.!?]$/.test(b)) return b + " " + tail;
      return b + " " + tail;
    }

    function localNewBullet(keyword, note, lang){
      const kw = prettyKeyword(keyword, lang);
      const n = normalizeSpaces(note);
      const de = isLikelyGerman(lang);
      const seed = hashString(keyword + "|" + note + "|" + lang);

      if(n){
        const templatesDe = [
          "Anwendung von " + kw + " (z. B. " + n + ").",
          n + " – mit Fokus auf " + kw + ".",
          "Umsetzung von " + kw + " im Kontext von " + n + "."
        ];
        const templatesEn = [
          "Applied " + kw + " (e.g., " + n + ").",
          n + " – with a focus on " + kw + ".",
          "Implemented " + kw + " in the context of " + n + "."
        ];
        return pick(de ? templatesDe : templatesEn, seed);
      }

      // If no note, be conservative
      return de
        ? ("Erfahrung mit " + kw + ".")
        : ("Experience with " + kw + ".");
    }

    /* -------------------------
       API helpers
       ------------------------- */

    const FETCH_TIMEOUT_MS = 45000;

    // Long-running AI endpoints can exceed 45s on slower devices/connections.
    // Keep a default timeout for normal calls, but allow longer timeouts for tailor/review.
    const TAILOR_TIMEOUT_MS  = 180000; // 3 min
    const REVIEW_TIMEOUT_MS  = 150000; // 2.5 min
    const KEYWORD_TIMEOUT_MS = 120000; // 2 min
    const JOB_CREATE_TIMEOUT_MS = 60000; // 60s

    const TOKEN_REFRESH_SKEW_SEC = 90;

    function timeoutForPath(path){
      const p = String(path || "");
      if(p.includes("/me/cv/tailor")) return TAILOR_TIMEOUT_MS;
      if(p.includes("/me/cv/review")) return REVIEW_TIMEOUT_MS;
      if(p.includes("/me/cv/keyword")) return KEYWORD_TIMEOUT_MS;
      if(p.includes("/me/jobs/create") || p.includes("/me/jobs/import") || p.includes("/me/jobs/create_from")) return JOB_CREATE_TIMEOUT_MS;
      return FETCH_TIMEOUT_MS;
    }

    function fetchWithTimeout(url, options = {}, timeoutMs = FETCH_TIMEOUT_MS){
      // AbortController is not supported on some older browsers/webviews.
      // In that case, fall back to a plain fetch (no client-side timeout).
      if(typeof AbortController !== "function" || !timeoutMs || timeoutMs <= 0){
        return fetch(url, options);
      }
      const controller = new AbortController();
      const t = setTimeout(() => { try{ controller.abort(); }catch(_){ } }, timeoutMs);
      return fetch(url, { ...options, signal: controller.signal })
        .finally(() => clearTimeout(t));
    }

    function isAbortError(e){
      if(!e) return false;
      if(e.name === "AbortError") return true;
      const msg = String(e.message || e || "");
      return /abort/i.test(msg);
    }

    function isNetworkishError(e){
      const msg = String(e?.message || e || "");
      const low = msg.toLowerCase();
      return (
        low.includes("failed to fetch") ||
        low.includes("network") ||
        low.includes("load failed") ||
        low.includes("connection") ||
        low.includes("canceled") ||
        low.includes("cancelled") ||
        isAbortError(e)
      );
    }

    function toNetworkError(path, e, timeoutMs){
      const msg = (e && e.message) ? String(e.message) : String(e||"");

      if(isAbortError(e)){
        const sec = timeoutMs ? Math.round(Number(timeoutMs)/1000) : 0;
        const err = new Error(
          path + " failed: request timed out" + (sec ? (" after " + sec + "s") : "") + ". " +
          "Please retry. If this keeps happening: check your connection, disable VPN/ad blockers, and verify API_BASE / CORS."
        );
        err.kind = "timeout";
        err.timeoutMs = timeoutMs || null;
        err.causeMsg = msg;
        return err;
      }

      if(isNetworkishError(e)){
        const err = new Error(
          path + " failed: network error. " +
          "If this keeps happening: check CORS on your Worker, disable VPN/ad blockers, and verify API_BASE."
        );
        err.kind = "network";
        err.timeoutMs = timeoutMs || null;
        err.causeMsg = msg;
        return err;
      }

      const err = new Error(path + " failed: " + msg);
      err.kind = "other";
      err.timeoutMs = timeoutMs || null;
      err.causeMsg = msg;
      return err;
    }

    async function getSessionFresh(forceRefresh = false){
      try{
        const auth = getAppAuth();
        if(!auth || !auth.getSession){
          return session || null;
        }

        let s = await auth.getSession();

        // Near-expiry refresh (best effort)
        const expiresAt = Number(s && s.expires_at ? s.expires_at : 0);
        const now = Math.floor(Date.now()/1000);
        const needsRefresh = forceRefresh || (expiresAt && (expiresAt - now) <= TOKEN_REFRESH_SKEW_SEC);

        if(needsRefresh){
          const sb = auth?.supabaseClient;
          if(sb && sb.auth && typeof sb.auth.refreshSession === "function"){
            const rr = await sb.auth.refreshSession();
            if(rr && rr.data && rr.data.session) s = rr.data.session;
          }
        }

        if(s && s.access_token){
          session = s;
          try{ sessionStorage.setItem("sb_access_token", s.access_token); }catch(_){}
        }
        return s || null;
      }catch(_){
        return session || null;
      }
    }

    async function authFetch(path, options = {}){
      const p = String(path || "");
      const url = API_BASE + p;

      // Support longer timeouts for AI-heavy endpoints (tailor/review/etc).
      // Caller can override with options.timeoutMs.
      const timeoutMs = Number(options.timeoutMs || timeoutForPath(p) || FETCH_TIMEOUT_MS);
      const { timeoutMs: _timeoutMs, ...opt } = options;

      const s1 = await getSessionFresh(false);
      const token1 = s1 && s1.access_token ? String(s1.access_token) : "";

      if(!token1){
        throw new Error(uiLang==="de" ? "Bitte anmelden." : "Please sign in.");
      }

      const headers1 = new Headers(opt.headers || {});
      headers1.set("Authorization", "Bearer " + token1);

      let res;
      try{
        res = await fetchWithTimeout(url, { ...opt, headers: headers1 }, timeoutMs);
      }catch(e){
        throw toNetworkError(p, e, timeoutMs);
      }

      // Retry once on 401 (token refresh)
      if(res.status === 401){
        const s2 = await getSessionFresh(true);
        const token2 = s2 && s2.access_token ? String(s2.access_token) : "";
        if(token2 && token2 !== token1){
          const headers2 = new Headers(opt.headers || {});
          headers2.set("Authorization", "Bearer " + token2);
          try{
            res = await fetchWithTimeout(url, { ...opt, headers: headers2 }, timeoutMs);
          }catch(e){
            throw toNetworkError(p, e, timeoutMs);
          }
        }
      }

      return res;
    }

    async function apiGet(path, options = {}){
      const res = await authFetch(path, { ...(options||{}), method:"GET" });
      const txt = await res.text().catch(()=> "");
      let json = null;
      try{ json = txt ? JSON.parse(txt) : null; }catch{ json = { raw: txt }; }
      if(!res.ok){
        const msg = path + " failed: " + res.status + " " + (json?.error || json?.details || json?.message || txt);
        const err = new Error(msg);
        err.status = res.status;
        err.body = json;
        throw err;
      }
      return json;
    }

    async function apiPostJson(path, body, options = {}){
      const headers = new Headers(options.headers || {});
      headers.set("content-type","application/json");
      const res = await authFetch(path, {
        ...((options||{})),
        method:"POST",
        headers,
        body: JSON.stringify(body || {})
      });
      const txt = await res.text().catch(()=> "");
      let json = null;
      try{ json = txt ? JSON.parse(txt) : null; }catch{ json = { raw: txt }; }
      if(!res.ok){
        const msg = path + " failed: " + res.status + " " + (json?.error || json?.details || json?.message || txt);
        const err = new Error(msg);
        err.status = res.status;
        err.body = json;
        throw err;
      }
      return json;
    }


    function isEndpointMissing(err){
      const s = Number(err?.status || 0);
      return s === 404 || s === 405;
    }

    function extractTextFromAiResponse(res){
      if(!res) return "";
      if(typeof res.rewritten_bullet === "string") return res.rewritten_bullet;
      if(typeof res.new_bullet === "string") return res.new_bullet;
      if(typeof res.text === "string") return res.text;
      if(typeof res.bullet === "string") return res.bullet;
      if(typeof res.output === "string") return res.output;
      if(res.result){
        const r = res.result;
        return r.rewritten_bullet || r.new_bullet || r.text || r.bullet || r.output || "";
      }
      return "";
    }

    async function tryAiRewriteOrCraft({ mode, keyword, lang, current_bullet, note, context }){
      // mode: "rewrite" | "new"
      const endpoints = [
        "/me/cv/keyword_polish",
        "/me/cv/keyword_boost",
        "/me/cv/keyword_inject",
        "/me/cv/keyword_insert"
      ];

      const payloadBase = {
        job_id: String(selectedJob?.id || ""),
        keyword: String(keyword || ""),
        language: String(lang || ""),
        lang: String(lang || ""),
        ui_language: String(uiLang || ""),
        mode: String(mode || ""),
        current_bullet: String(current_bullet || ""),
        note: String(note || ""),
        context: context || {}
      };

      for(const ep of endpoints){
        try{
          const res = await apiPostJson(ep, payloadBase);
          const out = extractTextFromAiResponse(res);
          if(out && String(out).trim()) return { ok:true, text:String(out).trim(), endpoint:ep };
        }catch(e){
          if(isEndpointMissing(e)) continue;
          // if endpoint exists but fails (401/500), don't silently swallow:
          throw e;
        }
      }
      return { ok:false, text:"", endpoint:"" };
    }

    /* -------------------------
       Tailor strength
       ------------------------- */
    function strengthValue(){
      const v = Number($("strengthRange").value);
      if (v === 0) return { key:"light", label:t("light"), help: uiLang==="de"
        ? "Kleine Verbesserungen, nah an deinem Original."
        : "Small improvements, keeps wording close to your original." };
      if (v === 2) return { key:"strong", label:t("aggressive"), help: uiLang==="de"
        ? "Stärkeres Rewriting für besseren Fit (immer noch wahrheitsgemäß)."
        : "Rewrites more strongly to highlight fit and align with job language (still truthful)." };
      return { key:"balanced", label:t("balanced"), help: uiLang==="de"
        ? "Verbessert Summary & Bullets ohne zu viel umzuschreiben."
        : "Improves summary and bullets to match the job, without over-rewriting." };
    }

    function setStrengthUi(){
      const v = Number($("strengthRange").value);
      const s = strengthValue();
      setText("strengthBadge", s.label);
      setText("strengthHint", s.help);

      const pills = $("strengthPills")?.querySelectorAll(".miniPill") || [];
      pills.forEach(p => p.classList.toggle("active", Number(p.getAttribute("data-s")) === v));

      try{ localStorage.setItem("cv_strength", String(v)); }catch{}
      if(jobSource === "paste"){
        try{ updatePasteQuality(); }catch(_){ }
      }else{
        try{ refreshModeUi(); }catch(_){ }
      }
    }

    function setTemplateUi(){
      try{ localStorage.setItem("cv_template", String($("tplSelect").value || "professional")); }catch{}
      if(jobSource === "paste"){
        try{ updatePasteQuality(); }catch(_){ }
      }
    }

    function setGenVizState(state){
  genStepsState = state || "idle";
  const el = $("genViz");
  if(!el) return;

  el.classList.remove("isIdle","isRunning","isDone","isError");
  if(genStepsState === "running") el.classList.add("isRunning");
  else if(genStepsState === "done") el.classList.add("isDone");
  else if(genStepsState === "error") el.classList.add("isError");
  else el.classList.add("isIdle");

  const chip = $("genVizChip");
  if(chip){
    const cls = (genStepsState === "running") ? "warn"
      : (genStepsState === "done") ? "good"
      : (genStepsState === "error") ? "bad" : "";
    chip.className = "badge" + (cls ? (" " + cls) : "");
    chip.textContent = (genStepsState === "running") ? (uiLang==="de" ? "Arbeite…" : "Working…")
      : (genStepsState === "done") ? (uiLang==="de" ? "Fertig" : "Done")
      : (genStepsState === "error") ? (uiLang==="de" ? "Fehlgeschlagen" : "Failed")
      : (uiLang==="de" ? "Bereit" : "Ready");
  }
}

function markSteps(state){
  try{ setGenVizState(state); }catch(_){ genStepsState = state || "idle"; }

  const ids = ["s1","s2","s3","s4","s5"];
  ids.forEach(id => {
    const el = $(id);
    if(!el) return;
    el.style.fontWeight = "750";
    el.style.color = "rgba(17,19,24,.72)";
  });

  const setBoth = (cls, txt) => {
    setBadge("stepsBadge", cls, txt);
    setBadge("genBadge", cls, txt);
  };

  if(state === "idle"){ setBoth("", uiLang==="de" ? "Bereit" : "Ready"); return; }
  if(state === "running"){ setBoth("warn", uiLang==="de" ? "Generiere…" : "Generating…"); return; }
  if(state === "done"){
    setBoth("good", uiLang==="de" ? "Fertig" : "Done");
    ids.forEach(id => {
      const el = $(id); if(!el) return;
      el.style.color = "#0a3d1f";
      el.style.fontWeight = "900";
    });
    if(genModalAuto) closeGenModal();
    return;
  }
  if(state === "error"){
    setBoth("bad", uiLang==="de" ? "Fehlgeschlagen" : "Failed");
    if(genModalAuto) closeGenModal();
    return;
  }
}

    function setOutputEnabled(enabled){
      $("btnCopy").disabled = !enabled;
      $("btnDownload").disabled = !enabled;
      $("btnQa").disabled = !enabled;
      $("btnPrint").disabled = !enabled;
      $("btnCopyMissing").disabled = !enabled;
      $("btnUndoEdit").disabled = !enabled;
      $("btnResetEdits").disabled = !enabled;
      try{ updateQaDot(); }catch(_){}

      // Keep the primary action label clear (avoid "two generate buttons" confusion)
      try{
        const genBtn = $("btnGenerate");
        if(genBtn && !gateActive){
          genBtn.textContent = enabled ? "Regenerate tailored CV" : "Generate tailored CV";
        }
      }catch(_){}
    }

    function updateUndoResetButtons(){
      const hasBase = !!baseSnapshot;
      $("btnResetEdits").disabled = !hasBase;
      $("btnUndoEdit").disabled = !(historyStack && historyStack.length);
    }

    /* -------------------------
       ATS score rendering
       ------------------------- */
    function computeAtsScore(used, missing){
      const u = Array.isArray(used) ? used.length : 0;
      const m = Array.isArray(missing) ? missing.length : 0;
      if(u + m <= 0) return null;
      return Math.round((u / (u + m)) * 100);
    }

    function renderKeywords(){
      const used = Array.isArray(lastUsed) ? lastUsed : [];
      const miss = Array.isArray(lastMissing) ? lastMissing : [];

      $("chipsUsed").innerHTML = used.length
        ? used.slice(0, 120).map(k => `<span class="chip good" title="${H.escapeHtml(k)}">${H.escapeHtml(prettyKeyword(k,lastLang))}</span>`).join("")
        : `<span class="hint">—</span>`;

      $("chipsMissing").innerHTML = miss.length
        ? miss.slice(0, 120).map(k => {
            const disp = prettyKeyword(k,lastLang);
            return `<button type="button" class="chip chipBtn warn" data-kw="${H.escapeHtml(k)}" title="${H.escapeHtml(k)}">
              <span style="min-width:0;overflow:hidden;text-overflow:ellipsis">${H.escapeHtml(disp)}</span>
              <span class="chipPlus" aria-hidden="true">＋</span>
            </button>`;
          }).join("")
        : `<span class="hint">—</span>`;

      setText("kwUsedCount", used.length ? String(used.length) : "0");
      setText("kwMissCount", miss.length ? String(miss.length) : "0");

      const score = computeAtsScore(used, miss);
      if(score == null){
        setText("atsScore", "—");
        $("atsBar").style.width = "0%";
      }else{
        setText("atsScore", score + "%");
        $("atsBar").style.width = score + "%";
      }
    }

    function recomputeCoverageFromCurrentText(){
      const text = $("cvText").value || "";
      const all = Array.isArray(atsKeywordsAll) && atsKeywordsAll.length
        ? atsKeywordsAll
        : Array.from(new Set([...(lastUsed||[]), ...(lastMissing||[])].map(x=>String(x||"").trim()).filter(Boolean)));

      const used = [];
      const miss = [];
      for(const kw of all){
        if(keywordInText(kw, text)) used.push(kw);
        else miss.push(kw);
      }
      lastUsed = used;
      lastMissing = miss;
      renderKeywords();
    }

    /* -------------------------
       CV doc formatting (ported from dashboard)
       ------------------------- */
    function cvLabels(lang){
      const de = isLikelyGerman(lang);
      return de ? {
        summary: "Profil",
        experience: "Experience",
        education: "Ausbildung",
        achievements: "Erfolge",
        skills: "Skills",
        courses: "Kurse",
        interests: "Interessen",
        languages: "Languagen"
      } : {
        summary: "Profile",
        experience: "Experience",
        education: "Education",
        achievements: "Key achievements",
        skills: "Skills",
        courses: "Courses",
        interests: "Interests",
        languages: "Languages"
      };
    }

    function ul(items){
      const arr = asStringArr(items, 999);
      if(!arr.length) return "";
      return `<ul class="cvUl">${arr.map(x => `<li>${H.escapeHtml(x)}</li>`).join("")}</ul>`;
    }

    function sec(title, inner){
      if(!inner || !String(inner).trim()) return "";
      return `<div class="cvSection"><div class="cvSectionTitle">${H.escapeHtml(title)}</div>${inner}</div>`;
    }

    function item(title, sub, meta, bullets){
      const t = String(title || "").trim();
      const s = String(sub || "").trim();
      const m = String(meta || "").trim();
      const b = asStringArr(bullets, 12);

      const parts = [];
      parts.push(`<div class="cvItem">`);
      if(t) parts.push(`<div class="cvItemTitle">${H.escapeHtml(t)}</div>`);
      if(s) parts.push(`<div class="cvItemSub">${H.escapeHtml(s)}</div>`);
      if(m) parts.push(`<div class="cvMetaLine">${H.escapeHtml(m)}</div>`);
      if(b.length) parts.push(ul(b));
      parts.push(`</div>`);
      return parts.join("");
    }

    function cvDocToPreviewHtml(doc, lang){
      const L = cvLabels(lang);
      const name = String(doc?.name || "YOUR NAME");
      const role = String(doc?.target_role || (isLikelyGerman(lang) ? "Die Rolle, auf die du dich bewirbst" : "The role you are applying for"));

      const c = doc?.contact || {};
      const contactLine = joinNonEmpty([c.phone, c.email, c.linkedin, c.portfolio, c.location], " · ");

      const summary = asStringArr(doc?.summary, 8);
      const exp = Array.isArray(doc?.experience) ? doc.experience : [];
      const edu = Array.isArray(doc?.education) ? doc.education : [];
      const ach = asStringArr(doc?.key_achievements, 10);

      const skills = doc?.skills || {};
      const skillGroups = Array.isArray(skills?.groups) ? skills.groups : [];
      const addSkills = asStringArr(skills?.additional, 24);

      const courses = asStringArr(doc?.courses, 12);
      const interests = asStringArr(doc?.interests, 12);
      const langs = asStringArr(doc?.languages, 12);

      const summaryHtml = summary.length ? `<p class="cvPara">${H.escapeHtml(summary.join(" "))}</p>` : "";

      const expHtml = exp.map(e => {
        const title = e?.title || "";
        const sub = joinNonEmpty([e?.company, e?.location], " · ");
        const meta = joinNonEmpty([e?.start, e?.end], " – ");
        return item(title, sub, meta, e?.bullets);
      }).join("");

      const eduHtml = edu.map(e => {
        const title = joinNonEmpty([e?.degree, e?.field], " · ");
        const sub = joinNonEmpty([e?.school, e?.location], " · ");
        const meta = joinNonEmpty([e?.start, e?.end], " – ");
        return item(title, sub, meta, e?.bullets);
      }).join("");

      const skillsInner = [
        skillGroups.map(g => {
          const label = String(g?.label || "").trim();
          const items = asStringArr(g?.items, 30);
          if(!items.length) return "";
          const line = label ? `${H.escapeHtml(label)}: ${H.escapeHtml(items.join(", "))}` : H.escapeHtml(items.join(", "));
          return `<div class="cvSkillLine">${line}</div>`;
        }).join(""),
        addSkills.length ? `<div class="cvSkillLine">${H.escapeHtml(addSkills.join(", "))}</div>` : ""
      ].join("");

      const coursesInner = courses.length ? `<div class="cvPara">${H.escapeHtml(courses.join(" · "))}</div>` : "";
      const interestsInner = interests.length ? `<div class="cvPara">${H.escapeHtml(interests.join(" · "))}</div>` : "";
      const langsInner = langs.length ? `<div class="cvPara">${H.escapeHtml(langs.join(" · "))}</div>` : "";

      return [
        `<div class="cvPreview">`,
        `<div class="cvName">${H.escapeHtml(name)}</div>`,
        `<div class="cvRole">${H.escapeHtml(role)}</div>`,
        contactLine ? `<div class="cvContact">${H.escapeHtml(contactLine)}</div>` : ``,
        sec(L.summary, summaryHtml),
        sec(L.experience, expHtml),
        sec(L.education, eduHtml),
        sec(L.achievements, ul(ach)),
        sec(L.skills, skillsInner),
        sec(L.courses, coursesInner),
        sec(L.interests, interestsInner),
        sec(L.languages, langsInner),
        `</div>`,
      ].join("");
    }

    function cvDocToPlainText(doc, lang){
      const L = cvLabels(lang);
      const lines = [];
      const name = String(doc?.name || "").trim();
      const role = String(doc?.target_role || "").trim();
      const c = doc?.contact || {};
      const contactLine = joinNonEmpty([c.phone, c.email, c.linkedin, c.portfolio, c.location], " · ");

      if(name) lines.push(name);
      if(role) lines.push(role);
      if(contactLine) lines.push(contactLine);
      if(lines.length) lines.push("");

      const summary = asStringArr(doc?.summary, 8);
      if(summary.length){
        lines.push(L.summary.toUpperCase());
        lines.push(summary.join(" "));
        lines.push("");
      }

      const exp = Array.isArray(doc?.experience) ? doc.experience : [];
      if(exp.length){
        lines.push(L.experience.toUpperCase());
        for(const e of exp){
          const t = String(e?.title || "").trim();
          const sub = joinNonEmpty([e?.company, e?.location], " · ");
          const meta = joinNonEmpty([e?.start, e?.end], " – ");
          if(t) lines.push(t);
          if(sub) lines.push(sub);
          if(meta) lines.push(meta);
          const b = asStringArr(e?.bullets, 12);
          for(const bb of b) lines.push("- " + bb);
          lines.push("");
        }
      }

      const edu = Array.isArray(doc?.education) ? doc.education : [];
      if(edu.length){
        lines.push(L.education.toUpperCase());
        for(const e of edu){
          const t = joinNonEmpty([e?.degree, e?.field], " · ");
          const sub = joinNonEmpty([e?.school, e?.location], " · ");
          const meta = joinNonEmpty([e?.start, e?.end], " – ");
          if(t) lines.push(t);
          if(sub) lines.push(sub);
          if(meta) lines.push(meta);
          const b = asStringArr(e?.bullets, 8);
          for(const bb of b) lines.push("- " + bb);
          lines.push("");
        }
      }

      const ach = asStringArr(doc?.key_achievements, 10);
      if(ach.length){
        lines.push(L.achievements.toUpperCase());
        for(const a of ach) lines.push("- " + a);
        lines.push("");
      }

      const skills = doc?.skills || {};
      const groups = Array.isArray(skills?.groups) ? skills.groups : [];
      const addSkills = asStringArr(skills?.additional, 24);
      const skillLines = [];
      for(const g of groups){
        const label = String(g?.label || "").trim();
        const items = asStringArr(g?.items, 30);
        if(!items.length) continue;
        skillLines.push(label ? (label + ": " + items.join(", ")) : items.join(", "));
      }
      if(addSkills.length) skillLines.push(addSkills.join(", "));
      if(skillLines.length){
        lines.push(L.skills.toUpperCase());
        for(const s of skillLines) lines.push(s);
        lines.push("");
      }

      const courses = asStringArr(doc?.courses, 12);
      if(courses.length){
        lines.push(L.courses.toUpperCase());
        lines.push(courses.join(" · "));
        lines.push("");
      }

      const interests = asStringArr(doc?.interests, 12);
      if(interests.length){
        lines.push(L.interests.toUpperCase());
        lines.push(interests.join(" · "));
        lines.push("");
      }

      const langs = asStringArr(doc?.languages, 12);
      if(langs.length){
        lines.push(L.languages.toUpperCase());
        lines.push(langs.join(" · "));
        lines.push("");
      }

      return lines.join("\n").trim() + "\n";
    }

    function cvTextToPrintableHtml(title, text){
      const safeTitle = H.escapeHtml(title || "Curriculum Vitae");
      const safeText = H.escapeHtml(String(text || "").trim());
      return `<!doctype html>
<html>
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>${safeTitle}</title>
<style>
  @page{ size:A4; margin:14mm 14mm 14mm 14mm; }
  body{ margin:0; padding:0; font-family: Arial, Helvetica, sans-serif; color:#111318; }
  .cvPaper{ max-width:820px; margin:0 auto; padding:0; }
  h1{ font-size:18px; margin:0 0 10px 0; }
  pre{ white-space:pre-wrap; font-size:12.5px; line-height:1.45; font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono","Courier New", monospace; }
</style>
</head>
<body>
  <div class="cvPaper">
    <h1>${safeTitle}</h1>
    <pre>${safeText}</pre>
  </div>
</body>
</html>`;
    }

    function cvDocToPrintableHtml(cvDoc, lang, title){
      const css = `
        @page{ size:A4; margin:14mm 14mm 14mm 14mm; }
        body{ margin:0; padding:0; font-family: Arial, Helvetica, sans-serif; color:#111318; }
        .cvPaper{ max-width:820px; margin:0 auto; }
        .cvName{ font-size:34px; font-weight:900; letter-spacing:-.6px; color:#111318; }
        .cvRole{ margin-top:2px; font-size:14px; font-weight:800; color:#3b3f46; }
        .cvContact{ margin-top:6px; font-size:12.5px; color:#3b3f46; }
        .cvSection{ margin-top:16px; }
        .cvSectionTitle{ font-size:14px; font-weight:900; letter-spacing:.04em; text-transform:uppercase; border-bottom:3px solid #111318; padding-bottom:6px; margin:0 0 8px 0; }
        .cvItem{ margin-top:10px; }
        .cvItemTitle{ font-size:13.5px; font-weight:900; }
        .cvItemSub{ margin-top:2px; font-size:12.5px; font-weight:800; color:#3b3f46; }
        .cvMetaLine{ margin-top:2px; font-size:12.5px; color:#3b3f46; }
        .cvUl{ margin:6px 0 0 18px; padding:0; }
        .cvUl li{ margin:0 0 3px 0; font-size:13px; }
        .cvPara{ font-size:13px; line-height:1.45; margin:0; }
        .cvSkillLine{ font-size:13px; line-height:1.45; margin:2px 0; }
      `;

      const safeTitle = H.escapeHtml(title || "Curriculum Vitae");
      const bodyHtml = cvDocToPreviewHtml(cvDoc, lang).replace('<div class="cvPreview">', '<div class="cvPaper">');

      return `<!doctype html>
<html>
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>${safeTitle}</title>
<style>${css}</style>
</head>
<body>
${bodyHtml}
</body>
</html>`;
    }

    function printHtml(html){
      const blob = new Blob([html], {type:'text/html'});
      const url = URL.createObjectURL(blob);
      let iframe = document.getElementById('printFrame');
      if(!iframe){
        iframe = document.createElement('iframe');
        iframe.id = 'printFrame';
        iframe.style.position='fixed';
        iframe.style.right='0';
        iframe.style.bottom='0';
        iframe.style.width='1px';
        iframe.style.height='1px';
        iframe.style.opacity='0';
        iframe.style.pointerEvents='none';
        document.body.appendChild(iframe);
      }
      iframe.onload = () => {
        try{
          iframe.contentWindow.focus();
          iframe.contentWindow.print();
        }catch(_){}
        setTimeout(()=>{ try{ URL.revokeObjectURL(url); }catch(_){} }, 1500);
      };
      iframe.src = url;
    }

    /* -------------------------
       Tabs + rendering
       ------------------------- */
    function setTabs(which){
      const isPreview = which === "preview";
      const isText = which === "text";
      const isChanges = which === "changes";

      $("tabPreview").classList.toggle("active", isPreview);
      $("tabText").classList.toggle("active", isText);
      $("tabChanges").classList.toggle("active", isChanges);

      $("cvPreviewWrap").style.display = isPreview ? "" : "none";
      $("cvTextWrap").style.display = isText ? "" : "none";
      $("cvChangesWrap").style.display = isChanges ? "" : "none";

      if(isChanges){
        renderChangesView();
      }
    }

    /* -------------------------
       Studio modes (Resume.io-inspired)
       - Tailor: keep UI calm (Preview only)
       - Edit: show Preview/Text/Changes tabs
       - AI Review: show review panel in Inspector
       ------------------------- */
    const studioRoot = $("studioRoot");
    let studioMode = "tailor";

    function setModeButton(activeId){
      const ids = ["modeEdit","modeCustomize","modeReview","modeTailor"];
      ids.forEach((id) => {
        const b = $(id);
        if(!b) return;
        const isActive = id === activeId;
        b.classList.toggle("active", isActive);
        b.setAttribute("aria-selected", isActive ? "true" : "false");
      });
    }

    function setStudioMode(mode){
      studioMode = mode || "tailor";
      if(studioRoot) studioRoot.setAttribute("data-mode", studioMode);

      if(studioMode === "edit"){
        setModeButton("modeEdit");
        // Default to Text editor for editing
        setTabs("text");
      }else if(studioMode === "review"){
        setModeButton("modeReview");
        setTabs("preview");
      }else if(studioMode === "customize"){
        setModeButton("modeCustomize");
        setTabs("preview");
      }else{
        setModeButton("modeTailor");
        setTabs("preview");
      }

      // Inspector header copy
      if(studioMode === "review"){
        $("inspectorTitle").textContent = "AI Review";
        $("inspectorHint").textContent = "Quick quality checks before you send or export. Open the full report for details.";
        $("inspectorBadge").textContent = "Review";
      }else{
        $("inspectorTitle").textContent = "Inspector";
        $("inspectorHint").textContent = "Your CV stays centered. Use this panel to improve ATS match and polish wording without getting overwhelmed.";
        $("inspectorBadge").textContent = "Live";
      }

      // Close the download dropdown if it's open (keeps things tidy)
      const dl = $("studioDownloadDrop");
      if(dl) dl.open = false;

      try { localStorage.setItem("jmj_cv_mode", studioMode); } catch(_) {}
    }

    /* -------------------------
       Changes / Diff view
       ------------------------- */
    function normText(t){
      return String(t || "")
        .replace(/\r\n/g, "\n")
        .replace(/[ \t]+/g, " ")
        .trim();
    }

    function splitLines(t){
      const s = String(t || "").replace(/\r\n/g,"\n");
      // Keep empty lines (important for CV structure)
      return s.split("\n");
    }

    // Simple LCS-based line diff: returns [{type:"same"|"add"|"del", line:string}]
    function diffLinesLcs(aText, bText){
      const A = splitLines(aText);
      const B = splitLines(bText);

      const n = A.length;
      const m = B.length;

      // Fast paths
      if(n === 0 && m === 0) return [];
      if(n === 0) return B.map(line => ({ type:"add", line }));
      if(m === 0) return A.map(line => ({ type:"del", line }));

      // DP table (n+1) x (m+1)
      // Keep it as Uint16Array per row for memory (CVs are small enough)
      const dp = Array.from({length: n+1}, () => new Uint16Array(m+1));

      for(let i=n-1; i>=0; i--){
        const row = dp[i];
        const rowNext = dp[i+1];
        for(let j=m-1; j>=0; j--){
          if(A[i] === B[j]) row[j] = rowNext[j+1] + 1;
          else row[j] = Math.max(rowNext[j], row[j+1]);
        }
      }

      const out = [];
      let i = 0, j = 0;
      while(i < n && j < m){
        if(A[i] === B[j]){
          out.push({ type:"same", line: A[i] });
          i++; j++;
        }else{
          const down = dp[i+1][j];
          const right = dp[i][j+1];
          if(down >= right){
            out.push({ type:"del", line: A[i] });
            i++;
          }else{
            out.push({ type:"add", line: B[j] });
            j++;
          }
        }
      }
      while(i < n){ out.push({ type:"del", line: A[i++] }); }
      while(j < m){ out.push({ type:"add", line: B[j++] }); }
      return out;
    }

    function countAddedSignals(diff){
      const added = diff.filter(d => d.type === "add").map(d => d.line).join("\n");
      const del = diff.filter(d => d.type === "del").map(d => d.line).join("\n");

      // Numbers/metrics (often risky if introduced without proof)
      const numRe = /\b\d{1,3}(?:[.,]\d{1,2})?(?:%|k|K|m|M)?\b/g;
      const addedNums = (added.match(numRe) || []).length;

      // Certification / qualification-like tokens (heuristic)
      const certTokens = [
        "PMP","PRINCE2","ITIL","AWS","AZ-","GCP","Google Cloud","Scrum Master","CSM","PSM",
        "CFA","CPA","CIPP","CISSP","OSCP","ISTQB","TOGAF","SAP Certified","MBA"
      ];
      let certHits = 0;
      for(const tok of certTokens){
        const re = new RegExp(String(tok).replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "i");
        if(re.test(added)) certHits += 1;
      }

      // Seniority inflation (heuristic)
      const seniorityHits = (added.match(/\b(Senior|Lead|Head of|Principal)\b/gi) || []).length;

      // Language claims (heuristic)
      const langClaimHits = (added.match(/\b(native|fluent|C2|C1|B2)\b/gi) || []).length;

      // How many lines changed
      const addLines = diff.filter(d => d.type === "add" && String(d.line||"").trim()).length;
      const delLines = diff.filter(d => d.type === "del" && String(d.line||"").trim()).length;

      return { addedNums, certHits, seniorityHits, langClaimHits, addLines, delLines, addedText: added, deletedText: del };
    }

    function assessReviewRisk(diff){
      const s = countAddedSignals(diff);
      let score = 0;

      if(s.addedNums > 0) score += 2;
      if(s.certHits > 0) score += 2;
      if(s.seniorityHits > 0) score += 1;
      if(s.langClaimHits > 0) score += 1;
      if(s.addLines + s.delLines > 18) score += 1;

      let level = "Low";
      let cls = "good";
      if(score >= 4){ level = "High"; cls = "bad"; }
      else if(score >= 2){ level = "Medium"; cls = "warn"; }

      // Confidence is inverse of risk score (simple)
      const confidence = Math.max(10, Math.min(100, 100 - score * 18));

      const notes = [];
      if(s.addedNums > 0) notes.push("New numbers/metrics detected");
      if(s.certHits > 0) notes.push("New certifications/qualifications detected");
      if(s.seniorityHits > 0) notes.push("Seniority wording changes detected");
      if(s.langClaimHits > 0) notes.push("Language proficiency claims detected");
      if(!notes.length) notes.push("Mostly wording/keyword changes");

      return { level, cls, confidence, notes, signals: s };
    }

    function fmtDelta(delta){
      if(delta == null || isNaN(delta)) return "";
      if(delta > 0) return `(+${delta})`;
      if(delta < 0) return `(${delta})`;
      return "(±0)";
    }

    function buildDocChanges(baseDoc, curDoc){
      const changes = [];
      if(!baseDoc || !curDoc) return changes;

      // Summary (array -> string compare)
      const baseSummary = Array.isArray(baseDoc.summary) ? baseDoc.summary.join(" ").trim() : String(baseDoc.summary||"").trim();
      const curSummary = Array.isArray(curDoc.summary) ? curDoc.summary.join(" ").trim() : String(curDoc.summary||"").trim();
      if(normText(baseSummary) !== normText(curSummary)){
        changes.push({
          id: "summary",
          kind: "summary",
          title: "Profile",
          meta: "Summary paragraph",
          before: baseSummary,
          after: curSummary
        });
      }

      // Experience bullets
      const baseExp = Array.isArray(baseDoc.experience) ? baseDoc.experience : [];
      const curExp = Array.isArray(curDoc.experience) ? curDoc.experience : [];
      const expN = Math.max(baseExp.length, curExp.length);

      for(let i=0; i<expN; i++){
        const be = baseExp[i] || null;
        const ce = curExp[i] || null;
        if(!be && !ce) continue;

        const label = [ce?.title || be?.title || "Role", ce?.company || be?.company || ""].filter(Boolean).join(" @ ").trim();
        const bBullets = Array.isArray(be?.bullets) ? be.bullets : [];
        const cBullets = Array.isArray(ce?.bullets) ? ce.bullets : [];
        const bn = bBullets.length;
        const cn = cBullets.length;
        const n = Math.max(bn, cn);

        for(let j=0; j<n; j++){
          const bb = (bBullets[j] == null) ? null : String(bBullets[j]);
          const cb = (cBullets[j] == null) ? null : String(cBullets[j]);
          if(bb === cb) continue;

          // Ignore trailing empty differences
          if(normText(bb) === "" && normText(cb) === "") continue;

          changes.push({
            id: `exp:${i}:${j}`,
            kind: "exp_bullet",
            expIndex: i,
            bulletIndex: j,
            title: "Experience",
            meta: `${label} • Bullet ${j+1}`,
            before: bb,
            after: cb
          });
        }
      }

      // Skills (groups + additional)
      const bSkills = baseDoc.skills || {};
      const cSkills = curDoc.skills || {};

      const bGroups = Array.isArray(bSkills.groups) ? bSkills.groups : [];
      const cGroups = Array.isArray(cSkills.groups) ? cSkills.groups : [];

      // map by label (case-insensitive), fallback to index
      const mapByLabel = (arr) => {
        const map = new Map();
        arr.forEach((g, idx) => {
          const key = String(g?.label || ("#"+idx)).trim().toLowerCase();
          map.set(key, { g, idx });
        });
        return map;
      };
      const bMap = mapByLabel(bGroups);
      const cMap = mapByLabel(cGroups);
      const allKeys = new Set([...bMap.keys(), ...cMap.keys()]);

      for(const key of allKeys){
        const bg = bMap.get(key)?.g || null;
        const cg = cMap.get(key)?.g || null;
        const label = String(cg?.label || bg?.label || "Skills").trim();
        const bItems = Array.isArray(bg?.items) ? bg.items.map(x=>String(x||"").trim()).filter(Boolean) : [];
        const cItems = Array.isArray(cg?.items) ? cg.items.map(x=>String(x||"").trim()).filter(Boolean) : [];

        // Compare as sets (order doesn't matter)
        const bSet = new Set(bItems.map(x=>x.toLowerCase()));
        const cSet = new Set(cItems.map(x=>x.toLowerCase()));
        const added = cItems.filter(x => !bSet.has(x.toLowerCase()));
        const removed = bItems.filter(x => !cSet.has(x.toLowerCase()));
        if(added.length || removed.length){
          changes.push({
            id: `skillsGroup:${key}`,
            kind: "skills_group",
            groupKey: key,
            groupLabel: label,
            title: "Skills",
            meta: label ? `Group: ${label}` : "Skill group",
            before: bItems.join(", "),
            after: cItems.join(", "),
            tags: [
              ...(added.length ? [`Added: ${added.slice(0,6).join(", ")}${added.length>6?"…":""}`] : []),
              ...(removed.length ? [`Removed: ${removed.slice(0,6).join(", ")}${removed.length>6?"…":""}`] : [])
            ]
          });
        }
      }

      const bAdd = Array.isArray(bSkills.additional) ? bSkills.additional.map(x=>String(x||"").trim()).filter(Boolean) : [];
      const cAdd = Array.isArray(cSkills.additional) ? cSkills.additional.map(x=>String(x||"").trim()).filter(Boolean) : [];
      const bAddSet = new Set(bAdd.map(x=>x.toLowerCase()));
      const cAddSet = new Set(cAdd.map(x=>x.toLowerCase()));
      const addAdded = cAdd.filter(x => !bAddSet.has(x.toLowerCase()));
      const addRemoved = bAdd.filter(x => !cAddSet.has(x.toLowerCase()));
      if(addAdded.length || addRemoved.length){
        changes.push({
          id: "skillsAdditional",
          kind: "skills_additional",
          title: "Skills",
          meta: "Additional skills line",
          before: bAdd.join(", "),
          after: cAdd.join(", "),
          tags: [
            ...(addAdded.length ? [`Added: ${addAdded.slice(0,6).join(", ")}${addAdded.length>6?"…":""}`] : []),
            ...(addRemoved.length ? [`Removed: ${addRemoved.slice(0,6).join(", ")}${addRemoved.length>6?"…":""}`] : [])
          ]
        });
      }

      return changes;
    }

    function detectManualTextEdits(){
      if(!lastCvDoc) return false;
      const docText = cvDocToPlainText(lastCvDoc, lastLang);
      const curText = $("cvText").value || "";
      return normText(docText) !== normText(curText);
    }

    function renderChangesView(){
      // If no baseline, show empty
      if(!baseSnapshot){
        $("changeKpis").innerHTML = `<span class="hint">Generate a CV to review changes.</span>`;
        $("changeCards").innerHTML = "";
        $("diffBox").textContent = "—";
        $("trustBar").style.width = "0%";
        $("trustHint").textContent = "—";
        $("btnCopyChangeSummary").disabled = true;
        $("btnUndoFromChanges").disabled = true;
        $("btnResetFromChanges").disabled = true;
        $("btnSyncTextToDoc").style.display = "none";
        return;
      }

      // Enable buttons
      $("btnCopyChangeSummary").disabled = false;
      $("btnUndoFromChanges").disabled = $("btnUndoEdit")?.disabled ?? false;
      $("btnResetFromChanges").disabled = $("btnResetEdits")?.disabled ?? false;

      const baseAts = computeAtsScore(baseSnapshot.used, baseSnapshot.missing);
      const curAts = computeAtsScore(lastUsed, lastMissing);

      const baseMiss = Array.isArray(baseSnapshot.missing) ? baseSnapshot.missing.length : 0;
      const curMiss = Array.isArray(lastMissing) ? lastMissing.length : 0;
      const missDelta = baseMiss - curMiss;

      const baseUsed = Array.isArray(baseSnapshot.used) ? baseSnapshot.used.length : 0;
      const curUsed = Array.isArray(lastUsed) ? lastUsed.length : 0;
      const usedDelta = curUsed - baseUsed;

      // Build diffs
      const baseText = String(baseSnapshot.cv_text || "");
      const curText = String($("cvText").value || "");
      const diff = diffLinesLcs(baseText, curText);

      // Risk
      const risk = assessReviewRisk(diff);
      $("trustBar").style.width = String(risk.confidence) + "%";
      $("trustHint").textContent = `Review risk: ${risk.level}. ${risk.notes.join(" · ")}.`;

      // Manual edits detection
      const manual = detectManualTextEdits();
      if(manual){
        $("btnSyncTextToDoc").style.display = "";
      }else{
        $("btnSyncTextToDoc").style.display = "none";
      }

      // KPIs
      const kpis = [];
      if(baseAts != null && curAts != null){
        const delta = curAts - baseAts;
        kpis.push(`<span class="changePill ${delta>=0 ? "good":"warn"}">ATS: ${baseAts}% → ${curAts}% ${fmtDelta(delta)}</span>`);
      }else if(curAts != null){
        kpis.push(`<span class="changePill">ATS: ${curAts}%</span>`);
      }else{
        kpis.push(`<span class="changePill">ATS: —</span>`);
      }

      kpis.push(`<span class="changePill ${missDelta>0 ? "good" : ""}">Missing keywords: ${baseMiss} → ${curMiss} ${fmtDelta(missDelta)}</span>`);
      kpis.push(`<span class="changePill ${usedDelta>0 ? "good" : ""}">Used keywords: ${baseUsed} → ${curUsed} ${fmtDelta(usedDelta)}</span>`);
      kpis.push(`<span class="changePill ${manual ? "warn" : ""}">${manual ? "Text edited manually" : "Text in sync"}</span>`);
      kpis.push(`<span class="changePill ${risk.cls}">Truth check: ${risk.level}</span>`);

      $("changeKpis").innerHTML = kpis.join("");

      // Structured doc changes (for per-bullet review)
      const docChanges = buildDocChanges(baseSnapshot.cv_doc, lastCvDoc);
      const showDocReview = !manual;

      if(!docChanges.length){
        $("changeCards").innerHTML = `<div class="hint">No structured changes detected.</div>`;
      }else{
        const baseMissingSet = new Set((baseSnapshot.missing || []).map(x => String(x||"").trim()).filter(Boolean));
        const cards = docChanges.slice(0, 120).map(ch => {
          const before = (ch.before == null) ? "" : String(ch.before);
          const after = (ch.after == null) ? "" : String(ch.after);

          // Tag any keywords newly introduced in this snippet
          const addedKws = [];
          const allKws = Array.isArray(atsKeywordsAll) ? atsKeywordsAll : [];
          for(const kw of allKws){
            if(!kw) continue;
            if(keywordInText(kw, after) && !keywordInText(kw, before)){
              const baseMissing = baseMissingSet.has(String(kw).trim());
              // prefer highlighting keywords that were missing at generation time
              if(baseMissing) addedKws.push(prettyKeyword(kw, lastLang));
              if(addedKws.length >= 6) break;
            }
          }

          const tags = [];
          if(addedKws.length) tags.push(`<span class="tag good">Added keywords: ${H.escapeHtml(addedKws.join(", "))}</span>`);
          if(Array.isArray(ch.tags)){
            for(const t of ch.tags.slice(0,3)){
              tags.push(`<span class="tag warn">${H.escapeHtml(String(t))}</span>`);
            }
          }

          const btn = showDocReview
            ? `<button class="btn small" type="button" data-revert-id="${H.escapeHtml(ch.id)}">Revert</button>`
            : `<button class="btn small" type="button" disabled title="Sync text to preview to enable per-change revert.">Revert</button>`;

          return `
            <div class="changeCard">
              <div class="changeCardTop">
                <div style="min-width:0">
                  <div class="changeTitle">${H.escapeHtml(ch.title)}</div>
                  <div class="changeMeta">${H.escapeHtml(ch.meta || "")}</div>
                </div>
                <div style="flex:0 0 auto; display:flex; gap:8px; align-items:center;">
                  ${btn}
                </div>
              </div>

              <div class="changeBody">
                <div class="changeBlock">
                  <div class="changeLabel">Before</div>
                  <div class="changeText">${H.escapeHtml(before || "—")}</div>
                </div>
                <div class="changeBlock">
                  <div class="changeLabel">After</div>
                  <div class="changeText">${H.escapeHtml(after || "—")}</div>
                  ${tags.length ? `<div class="changeTags">${tags.join("")}</div>` : ``}
                </div>
              </div>
            </div>
          `;
        }).join("");

        $("changeCards").innerHTML = cards;

        if(manual){
          $("changeCards").insertAdjacentHTML("afterbegin", `
            <div class="changeCard" style="border-color: rgba(255,179,0,.28); background: rgba(255,179,0,.06);">
              <div class="changeTitle">Heads up: Text tab edits are active</div>
              <div class="changeMeta">
                You edited the CV text manually. Preview is still based on the structured CV.
                If you want to revert changes per bullet safely, click “Sync text to preview”.
              </div>
            </div>
          `);
        }
      }

      // Render advanced diff
      const diffHtml = diff.slice(0, 1500).map(d => {
        const prefix = d.type === "add" ? "+ " : (d.type === "del" ? "- " : "  ");
        const cls = d.type === "add" ? "add" : (d.type === "del" ? "del" : "same");
        return `<span class="diffLine ${cls}">${H.escapeHtml(prefix + (d.line ?? ""))}</span>`;
      }).join("");

      $("diffBox").innerHTML = diffHtml ? `<div class="diffLines">${diffHtml}</div>` : "—";

      // Set hint
      const changedLines = diff.filter(d => d.type !== "same" && String(d.line||"").trim()).length;
      $("changesHint").textContent = changedLines
        ? `Review what changed since the last generation. (${changedLines} changed lines)`
        : "No textual changes since the last generation.";

      // Keep buttons state in sync with main Undo/Reset
      $("btnUndoFromChanges").disabled = $("btnUndoEdit")?.disabled ?? true;
      $("btnResetFromChanges").disabled = $("btnResetEdits")?.disabled ?? true;
    }

    function revertStructuredChange(changeId){
      if(!baseSnapshot || !baseSnapshot.cv_doc || !lastCvDoc) return;
      const manual = detectManualTextEdits();
      if(manual){
        showError("You edited the Text tab manually. Click “Sync text to preview” first to enable per-change revert safely.");
        return;
      }

      const baseDoc = baseSnapshot.cv_doc;
      const curDoc = lastCvDoc;

      // Find the matching change item (recompute)
      const changes = buildDocChanges(baseDoc, curDoc);
      const ch = changes.find(x => String(x.id) === String(changeId));
      if(!ch) return;

      // Save history
      historyStack.push(snapshotCurrent());
      updateUndoResetButtons();

      try{
        if(ch.kind === "summary"){
          curDoc.summary = deepCopy(baseDoc.summary);
        }else if(ch.kind === "exp_bullet"){
          const i = ch.expIndex;
          const j = ch.bulletIndex;
          const bExp = Array.isArray(baseDoc.experience) ? baseDoc.experience : [];
          const cExp = Array.isArray(curDoc.experience) ? curDoc.experience : [];
          if(!cExp[i]) return;

          const bBullets = Array.isArray(bExp[i]?.bullets) ? bExp[i].bullets : [];
          const cBullets = Array.isArray(cExp[i]?.bullets) ? cExp[i].bullets : [];

          const bb = (bBullets[j] == null) ? null : String(bBullets[j]);
          const cb = (cBullets[j] == null) ? null : String(cBullets[j]);

          if(bb == null && cb != null){
            // Added bullet -> remove
            cBullets.splice(j, 1);
          }else if(bb != null && cb == null){
            // Removed bullet -> insert back
            cBullets.splice(j, 0, bb);
          }else{
            // Edited -> restore
            cBullets[j] = bb;
          }

          cExp[i].bullets = cBullets;
          curDoc.experience = cExp;
        }else if(ch.kind === "skills_group"){
          const bSkills = baseDoc.skills || {};
          const cSkills = curDoc.skills || {};
          const bGroups = Array.isArray(bSkills.groups) ? bSkills.groups : [];
          const cGroups = Array.isArray(cSkills.groups) ? cSkills.groups : [];

          // locate group in current by key
          const key = String(ch.groupKey || "").trim().toLowerCase();
          const keyOf = (g, idx) => String(g?.label || ("#"+idx)).trim().toLowerCase();

          const bIdx = bGroups.findIndex((g, idx) => keyOf(g, idx) === key);
          const cIdx = cGroups.findIndex((g, idx) => keyOf(g, idx) === key);

          if(cIdx === -1){
            // nothing to revert
          }else if(bIdx === -1){
            // group did not exist in base -> remove group
            cGroups.splice(cIdx, 1);
          }else{
            // restore items to base
            cGroups[cIdx].items = deepCopy(bGroups[bIdx].items || []);
          }

          curDoc.skills = { ...(cSkills||{}), groups: cGroups };
        }else if(ch.kind === "skills_additional"){
          const bSkills = baseDoc.skills || {};
          const cSkills = curDoc.skills || {};
          curDoc.skills = { ...(cSkills||{}), additional: deepCopy(bSkills.additional || []) };
        }

        // Re-render + sync text to doc
        $("cvPreview").innerHTML = cvDocToPreviewHtml(curDoc, lastLang);
        $("cvText").value = cvDocToPlainText(curDoc, lastLang);

        // Keep keyword coverage in sync
        recomputeCoverageFromCurrentText();

        // Re-render changes view if active
        if($("tabChanges").classList.contains("active")){
          renderChangesView();
        }
      }catch(e){
        showError(e?.message || String(e));
      }
    }

    async function copyChangeSummary(){
      if(!baseSnapshot) return;
      const baseAts = computeAtsScore(baseSnapshot.used, baseSnapshot.missing);
      const curAts = computeAtsScore(lastUsed, lastMissing);

      const baseMiss = Array.isArray(baseSnapshot.missing) ? baseSnapshot.missing.length : 0;
      const curMiss = Array.isArray(lastMissing) ? lastMissing.length : 0;

      const baseUsed = Array.isArray(baseSnapshot.used) ? baseSnapshot.used.length : 0;
      const curUsed = Array.isArray(lastUsed) ? lastUsed.length : 0;

      const baseText = String(baseSnapshot.cv_text || "");
      const curText = String($("cvText").value || "");
      const diff = diffLinesLcs(baseText, curText);
      const risk = assessReviewRisk(diff);

      const lines = [];
      const jm = getActiveJobMeta();
      if(jm?.title) lines.push(`Job: ${jm.title}` + (jm.company_name ? ` · ${jm.company_name}` : ""));
      if(baseAts != null && curAts != null) lines.push(`ATS match: ${baseAts}% → ${curAts}%`);
      else if(curAts != null) lines.push(`ATS match: ${curAts}%`);

      lines.push(`Keywords used: ${baseUsed} → ${curUsed}`);
      lines.push(`Keywords missing: ${baseMiss} → ${curMiss}`);
      lines.push(`Truth check: ${risk.level}`);

      const topMissing = Array.isArray(lastMissing) ? lastMissing.slice(0, 10) : [];
      if(topMissing.length) lines.push(`Top missing keywords: ${topMissing.map(k => prettyKeyword(k,lastLang)).join(", ")}`);

      await copyTextToClipboard(lines.join("\n"));
      $("btnCopyChangeSummary").textContent = "Copied ✓";
      setTimeout(()=>{ $("btnCopyChangeSummary").textContent = "Copy summary"; }, 900);
    }

    async function copyDiffToClipboard(){
      if(!baseSnapshot) return;
      const baseText = String(baseSnapshot.cv_text || "");
      const curText = String($("cvText").value || "");
      const diff = diffLinesLcs(baseText, curText);

      const out = diff.map(d => {
        const prefix = d.type === "add" ? "+ " : (d.type === "del" ? "- " : "  ");
        return prefix + String(d.line ?? "");
      }).join("\n");

      await copyTextToClipboard(out);
      $("btnCopyDiff").textContent = "Copied ✓";
      setTimeout(()=>{ $("btnCopyDiff").textContent = "Copy diff"; }, 900);
    }

    function syncTextToPreview(){
      if(!lastCvDoc) return;
      $("cvText").value = cvDocToPlainText(lastCvDoc, lastLang);
      recomputeCoverageFromCurrentText();
      showError("");


      renderChangesView();
    }


    function setCvOutput({ text, doc, lang }){
      lastCvText = String(text || "").trim();
      lastCvDoc = doc || null;
      lastLang = lang || "en";

      // New CV output => QA should run again
      qaLastRunAt = 0;
      qaLastHash = "";
      qaLastReport = null;
      qaPendingAction = "";

      // Preview
      if(lastCvDoc){
        $("cvPreview").innerHTML = cvDocToPreviewHtml(lastCvDoc, lastLang);
      }else{
        $("cvPreview").innerHTML = `<div class="hint">${uiLang==="de" ? "Keine strukturierte Preview verfügbar. Zeige Text." : "No structured preview available. Showing text only."}</div>`;
      }

      // Text view
      const textOut = lastCvDoc ? cvDocToPlainText(lastCvDoc, lastLang) : lastCvText;
      $("cvText").value = textOut || "";

      setOutputEnabled(!!(textOut && textOut.trim()));
      updateUndoResetButtons();
      if($("tabChanges")?.classList?.contains("active")){ try{ renderChangesView(); }catch(_){ } }
    }

    function snapshotCurrent(){
      return {
        at: Date.now(),
        cv_doc: deepCopy(lastCvDoc),
        cv_text: $("cvText").value || "",
        lang: lastLang,
        used: Array.isArray(lastUsed) ? [...lastUsed] : [],
        missing: Array.isArray(lastMissing) ? [...lastMissing] : [],
        all: Array.isArray(atsKeywordsAll) ? [...atsKeywordsAll] : []
      };
    }

    function restoreSnapshot(snap){
      if(!snap) return;
      lastCvDoc = deepCopy(snap.cv_doc);
      lastLang = snap.lang || lastLang || "en";
      $("cvText").value = String(snap.cv_text || "");
      lastUsed = Array.isArray(snap.used) ? snap.used : [];
      lastMissing = Array.isArray(snap.missing) ? snap.missing : [];
      atsKeywordsAll = Array.isArray(snap.all) ? snap.all : atsKeywordsAll;

      // rerender preview from doc if possible
      if(lastCvDoc) $("cvPreview").innerHTML = cvDocToPreviewHtml(lastCvDoc, lastLang);
      renderKeywords();
      updateUndoResetButtons();
    }

    /* -------------------------
       Queue loading
       ------------------------- */
    async function loadQueue(){
      const resp = await apiGet("/me/jobs/queue");
      jobs = Array.isArray(resp?.data) ? resp.data : [];
      const sel = $("jobSelect");
      sel.innerHTML = "";

      if(!jobs.length){
        sel.innerHTML = `<option value="">${uiLang==="de" ? "Keine Jobs in der Queue" : "No jobs in queue"}</option>`;
        setText("jobHint", uiLang==="de" ? "Keine Jobs gefunden. Öffne Jobs und lade neue Jobs." : "No jobs found. Go to Jobs and fetch new jobs.");
        setText("jobMeta", "");
        selectedJob = null;

        if(jobSource === "queue"){
          $("btnGenerate").disabled = true;
          $("btnGenerateAgain").disabled = true;
          $("btnViewDesc").disabled = true;
          $("btnCopyDesc").disabled = true;
        }else{
          // Paste mode can still be used even with an empty queue
          refreshModeUi();
        }
        return;
      }

      for(const j of jobs){
        const label = [j.title || (uiLang==="de" ? "Ohne Titel" : "Untitled"), j.company_name || (uiLang==="de" ? "Firma" : "Company")].filter(Boolean).join(" · ");
        const opt = document.createElement("option");
        opt.value = String(j.id);
        opt.textContent = label;
        sel.appendChild(opt);
      }

      const urlJobId = (qs("job_id") || "").trim();
      const storedJobId = (localStorage.getItem("cvstudio_selected_job_id") || "").trim();
      const preferred = urlJobId || storedJobId;

      if(preferred && jobs.some(j => String(j.id) === String(preferred))){
        sel.value = preferred;
      } else {
        sel.value = String(jobs[0].id);
      }

      await onJobChange();
    }

    async function onJobChange(){
      const jobId = $("jobSelect").value;
      selectedJob = jobs.find(j => String(j.id) === String(jobId)) || null;

      // If user is in paste mode, keep the queue selection in memory but don't change UI state.
      if(jobSource !== "queue"){
        return;
      }

      if(!selectedJob){
        setText("jobMeta", "");
        $("btnGenerate").disabled = true;
        $("btnGenerateAgain").disabled = true;
        $("btnViewDesc").disabled = true;
        $("btnCopyDesc").disabled = true;
        return;
      }

      try{ localStorage.setItem("cvstudio_selected_job_id", String(selectedJob.id)); }catch{}

      const meta = [
        selectedJob.company_name ? String(selectedJob.company_name) : null,
        formatLoc(selectedJob) || null
      ].filter(Boolean).join(" · ");

      setText("jobHint", (uiLang==="de" ? "Ausgewählt: " : "Selected: ") + (selectedJob.title || (uiLang==="de" ? "Job" : "Job")));
      setText("jobMeta", meta ? meta : "");

      $("btnGenerate").disabled = false;
      $("btnGenerateAgain").disabled = false;
      $("btnViewDesc").disabled = false;
      $("btnCopyDesc").disabled = false;

      // Restore last from localStorage for this job (best effort)
      try{
        const key = "cvstudio_last_" + String(selectedJob.id);
        const raw = localStorage.getItem(key);
        if(raw){
          const obj = JSON.parse(raw);
          if(obj && (obj.cv_doc || obj.cv_text)){
            lastUsed = Array.isArray(obj.used) ? obj.used : [];
            lastMissing = Array.isArray(obj.missing) ? obj.missing : [];
            atsKeywordsAll = Array.isArray(obj.all) ? obj.all : Array.from(new Set([...(lastUsed||[]), ...(lastMissing||[])]));

            renderKeywords();

            setCvOutput({ text: obj.cv_text || "", doc: obj.cv_doc || null, lang: obj.lang || obj.language || "en" });
            setBadge("outStatus","good", uiLang==="de" ? "Bereit (lokal)" : "Ready (local)");
            setText("outModel","Model: —");
            setText("outHint", uiLang==="de"
              ? "Letzten CV von diesem Gerät geladen. Generiere neu für ein frisches Ergebnis."
              : "Loaded your last tailored CV from this device. Generate to refresh from server."
            );

            baseSnapshot = snapshotCurrent();
            historyStack = [];
            updateUndoResetButtons();
          }
        }
      }catch(_){}

      try{ updateSourceChip(); }catch(_){}
    }

    function buildTailorPayload(){
      // IMPORTANT: keep payload minimal to avoid breaking strict backends
      const tpl = String($("tplSelect").value || "professional").trim().toLowerCase();
      const s = strengthValue();
      return { job_id: String(selectedJob?.id || ""), template: tpl, strength: s.key };
    }

    /* -------------------------
       Generate
       ------------------------- */
    async function generate(){
      showError("");

      // If an auto-start timer is pending, stop it (avoid double-run).
      try{ clearAutoStartTimer(); showAutoStartBar(false); }catch(_){ }

      try{ setGuidedSettingsGlow(false); }catch(_){ }



      if(jobSource === "paste"){
        await generateFromPaste();
        return;
      }

      if(!selectedJob){
        showError(t("pickJob"));
        return;
      }

      // Leaving Step 1 gate (if active) opens the full studio view
      exitGate();

      setSetupCollapsed(true, { persist:false });
      openGenModal(true);
      markSteps("running");
      setBadge("outStatus", "warn", uiLang==="de" ? "Generiere…" : "Generating…");
      setText("outHint", uiLang==="de" ? "Dein CV wird erstellt…" : "Generating your tailored CV…");
      setText("debugBox", "—");
      setBadge("pipeBadge", "warn", uiLang==="de" ? "Arbeite…" : "Working…");

      $("btnGenerate").disabled = true;
      $("btnGenerateAgain").disabled = true;

      try{
        const payload = buildTailorPayload();

        // Prime job-description cache (reduces first-run delays when coming from Jobs)
        try{
          await apiGet("/me/jobs/description?job_id=" + encodeURIComponent(String(payload.job_id)), { timeoutMs: 90000 });
        }catch(_){ /* best effort */ }

        const res = await apiPostJson("/me/cv/tailor", payload);

        if(!res || res.ok !== true){
          throw new Error(res?.error || "CV tailoring failed");
        }

        const r = res.result || {};
        const text = String(r.cv_text || "").trim();
        const doc = r.cv_doc || null;
        const lang = r.language || "en";

        lastUsed = Array.isArray(r.ats_keywords_used) ? r.ats_keywords_used : [];
        lastMissing = Array.isArray(r.ats_keywords_missing) ? r.ats_keywords_missing : [];
        atsKeywordsAll = Array.from(new Set([...(lastUsed||[]), ...(lastMissing||[])].map(x=>String(x||"").trim()).filter(Boolean)));

        lastDebug = {
          cached: !!res.cached,
          cache_age_seconds: res.cache_age_seconds ?? null,
          model: r.model || null,
          prompt_version: r.prompt_version || null,
          language: lang || null,
          desc_cache_status: r.desc_cache_status || null,
          cv_clean_status: r.cv_clean_status || null,
          cv_clean_model: r.cv_clean_model || null,
          cv_structured_status: r.cv_structured_status || null,
          cv_structured_model: r.cv_structured_model || null
        };

        renderKeywords();
        setCvOutput({ text, doc, lang });

        // Reset edit history on each new generation
        baseSnapshot = snapshotCurrent();
        historyStack = [];
        updateUndoResetButtons();

        setBadge("outStatus", "good", res.cached ? (uiLang==="de" ? "Bereit (cached)" : "Ready (cached)") : (uiLang==="de" ? "Bereit" : "Ready"));
        setText("outModel", "Model: " + (r.model || "—"));
        setText("outHint", res.cached
          ? (uiLang==="de"
            ? "Cached Ergebnis geladen. Ändere die Stärke, um eine neue Version zu erstellen."
            : "Loaded cached result. Change strength to create a different version.")
          : (uiLang==="de"
            ? "Neuer Tailored CV erstellt. Bitte prüfen und exportieren."
            : "Generated a new tailored CV. Review and export below.")
        );
        markSteps("done");

        const lines = [
          "Job description: " + String(r.desc_cache_status || "—"),
          "CV clean: " + String(r.cv_clean_status || "—") + (r.cv_clean_model ? (" (" + r.cv_clean_model + ")") : ""),
          "CV structured: " + String(r.cv_structured_status || "—") + (r.cv_structured_model ? (" (" + r.cv_structured_model + ")") : ""),
          res.cached ? ("Cache: used (" + String(res.cache_age_seconds || "0") + "s old)") : "Cache: generated"
        ];
        $("pipeBox").textContent = lines.join("\n");
        setBadge("pipeBadge", "good", "OK");

        $("debugBox").textContent = JSON.stringify({ ok:true, ...lastDebug }, null, 2);

        // Save last output locally (best effort)
        try{
          const key = "cvstudio_last_" + String(payload.job_id);
          localStorage.setItem(key, JSON.stringify({
            at: Date.now(),
            payload,
            cv_text: $("cvText").value || "",
            cv_doc: lastCvDoc,
            lang: lastLang,
            used: lastUsed,
            missing: lastMissing,
            all: atsKeywordsAll,
            debug: lastDebug
          }));
        }catch(_){}
      }catch(e){
        markSteps("error");
        setBadge("outStatus","bad", uiLang==="de" ? "Fehler" : "Failed");
        setBadge("pipeBadge","bad", uiLang==="de" ? "Fehler" : "Failed");
        showError(e?.message || String(e));
        $("debugBox").textContent = JSON.stringify({ ok:false, kind: e?.kind || null, timeoutMs: e?.timeoutMs || null, error: e?.message || String(e) }, null, 2);

        let hint = uiLang==="de"
          ? "Generierung fehlgeschlagen. Prüfe CV Upload und Jobbeschreibung."
          : "Failed to generate. Check your CV upload and job description availability.";

        if(e && e.kind === "timeout"){
          hint = uiLang==="de"
            ? "Zeitüberschreitung. Die Generierung läuft möglicherweise noch - klicke \"Generate again\", um das Ergebnis (cached) abzurufen."
            : "Timed out. The server may still be finishing - click \"Generate again\" to fetch the cached result.";
        }else if(e && e.kind === "network"){
          hint = uiLang==="de"
            ? "Netzwerkfehler. Prüfe deine Verbindung (VPN/Ad-Blocker) und versuche es erneut."
            : "Network error. Check your connection (VPN/ad blockers) and try again.";
        }

        setText("outHint", hint);
      }finally{
        $("btnGenerate").disabled = false;
        $("btnGenerateAgain").disabled = false;
      }
    }

    
    function isMissingEndpointError(e){
      const msg = String(e?.message || e || "");
      return /failed:\s*404\b/.test(msg) || /failed:\s*405\b/.test(msg);
    }

    function buildTailorFromTextPayload(){
      // keep payload minimal + explicit; backend should treat job_description as untrusted text
      const tpl = String($("tplSelect").value || "professional").trim().toLowerCase();
      const s = strengthValue();

      const job_title = String($("pasteTitle")?.value || "").trim();
      const company_name = String($("pasteCompany")?.value || "").trim();
      const apply_url = applyUrlSafe(String($("pasteApply")?.value || "").trim());
      const language_hint = String($("pasteLangHint")?.value || "auto").trim().toLowerCase();
      const job_description = getPasteDesc();

      return {
        template: tpl,
        strength: s.key,
        job_title,
        company_name,
        apply_url,
        language_hint,
        job_description
      };
    }

    async function generateFromPaste(){
      showError("");

      const desc = getPasteDesc();

      if(desc.length > 20000){
        showError(t("pasteTooLong"));
        return;
      }
      if(desc.length < 120){
        // We allow small texts in UI, but tailoring quality drops sharply below this.
        showError(t("pasteTooShort"));
        return;
      }

      // Leaving Step 1 gate (if active) opens the full studio view
      exitGate();

      setSetupCollapsed(true, { persist:false });
      openGenModal(true);
      markSteps("running");
      setBadge("outStatus", "warn", uiLang==="de" ? "Generiere…" : "Generating…");
      setText("outHint", uiLang==="de" ? "Dein CV wird erstellt…" : "Generating your tailored CV…");
      setText("debugBox", "—");
      setBadge("pipeBadge", "warn", uiLang==="de" ? "Arbeite…" : "Working…");

      $("btnGenerate").disabled = true;
      $("btnGenerateAgain").disabled = true;

      try{
        const payload = buildTailorFromTextPayload();

        // Try common endpoint names (so you can roll this out without changing the frontend again)
        const endpoints = [
          "/me/cv/tailor_from_text",
          "/me/cv/tailor-from-text",
          "/me/cv/tailor_text"
        ];

        let res = null;
        let usedEndpoint = null;

        for(const ep of endpoints){
          try{
            res = await apiPostJson(ep, payload);
            usedEndpoint = ep;
            break;
          }catch(e){
            if(isMissingEndpointError(e)) continue;
            throw e;
          }
        }

        // Optional fallback: create a temporary job on the backend, then call the existing tailor endpoint.
        // Implement one of these endpoints if you prefer that architecture.
        if(!res){
          const createEndpoints = [
            "/me/jobs/create_from_text",
            "/me/jobs/import_text",
            "/me/jobs/create_from_desc",
            "/me/jobs/create_from_description"
          ];

          const createPayload = {
            title: payload.job_title || "Pasted job",
            company_name: payload.company_name || "",
            apply_url: payload.apply_url || "",
            description: payload.job_description,
            language_hint: payload.language_hint || "auto",
            source: "pasted"
          };

          for(const ep of createEndpoints){
            try{
              const r0 = await apiPostJson(ep, createPayload);
              const tmpJobId = r0?.job_id || r0?.id || r0?.data?.id || r0?.job?.id || r0?.result?.job_id || null;
              if(tmpJobId){
                usedEndpoint = ep + " + /me/cv/tailor";
                res = await apiPostJson("/me/cv/tailor", { job_id: String(tmpJobId), template: payload.template, strength: payload.strength });
                break;
              }
            }catch(e){
              if(isMissingEndpointError(e)) continue;
              throw e;
            }
          }
        }

        if(!res){
          throw new Error(t("pasteNotSupported"));
        }

        if(!res || res.ok !== true){
          throw new Error(res?.error || "CV tailoring failed");
        }

        const r = res.result || {};
        const text = String(r.cv_text || "").trim();
        const doc = r.cv_doc || null;
        const lang = r.language || payload.language_hint || "en";

        lastUsed = Array.isArray(r.ats_keywords_used) ? r.ats_keywords_used : [];
        lastMissing = Array.isArray(r.ats_keywords_missing) ? r.ats_keywords_missing : [];
        atsKeywordsAll = Array.from(new Set([...(lastUsed||[]), ...(lastMissing||[])].map(x=>String(x||"").trim()).filter(Boolean)));

        lastDebug = {
          cached: !!res.cached,
          cache_age_seconds: res.cache_age_seconds ?? null,
          model: r.model || null,
          prompt_version: r.prompt_version || null,
          language: lang || null,
          job_source: "paste",
          tailor_endpoint: usedEndpoint || "unknown",
          desc_cache_status: r.desc_cache_status || "pasted",
          cv_clean_status: r.cv_clean_status || null,
          cv_clean_model: r.cv_clean_model || null,
          cv_structured_status: r.cv_structured_status || null,
          cv_structured_model: r.cv_structured_model || null
        };

        renderKeywords();
        setCvOutput({ text, doc, lang });

        // Reset edit history on each new generation
        baseSnapshot = snapshotCurrent();
        historyStack = [];
        updateUndoResetButtons();

        setBadge("outStatus", "good", res.cached ? (uiLang==="de" ? "Bereit (cached)" : "Ready (cached)") : (uiLang==="de" ? "Bereit" : "Ready"));
        setText("outModel", "Model: " + (r.model || "—"));
        setText("outHint", res.cached
          ? (uiLang==="de"
            ? "Cached Ergebnis geladen. Ändere die Stärke, um eine neue Version zu erstellen."
            : "Loaded cached result. Change strength to create a different version.")
          : (uiLang==="de"
            ? "Neuer Tailored CV erstellt. Bitte prüfen und exportieren."
            : "Generated a new tailored CV. Review and export below.")
        );
        markSteps("done");

        const lines = [
          "Job description: pasted",
          "Tailor endpoint: " + String(usedEndpoint || "—"),
          "CV clean: " + String(r.cv_clean_status || "—") + (r.cv_clean_model ? (" (" + r.cv_clean_model + ")") : ""),
          "CV structured: " + String(r.cv_structured_status || "—") + (r.cv_structured_model ? (" (" + r.cv_structured_model + ")") : ""),
          res.cached ? ("Cache: used (" + String(res.cache_age_seconds || "0") + "s old)") : "Cache: generated"
        ];
        $("pipeBox").textContent = lines.join("\n");
        setBadge("pipeBadge", "good", "OK");

        $("debugBox").textContent = JSON.stringify({ ok:true, ...lastDebug }, null, 2);

        // Save last output locally (best effort)
        try{
          const key = pasteCacheKey || ("cvstudio_last_paste_" + fnv1a(desc));
          localStorage.setItem(key, JSON.stringify({
            at: Date.now(),
            payload,
            cv_text: $("cvText").value || "",
            cv_doc: lastCvDoc,
            lang: lastLang,
            used: lastUsed,
            missing: lastMissing,
            all: atsKeywordsAll,
            debug: lastDebug
          }));
        }catch(_){}
      }catch(e){
        markSteps("error");
        setBadge("outStatus","bad", uiLang==="de" ? "Fehler" : "Failed");
        setBadge("pipeBadge","bad", uiLang==="de" ? "Fehler" : "Failed");
        showError(e?.message || String(e));
        $("debugBox").textContent = JSON.stringify({ ok:false, error: e?.message || String(e) }, null, 2);
        setText("outHint", uiLang==="de" ? "Generierung fehlgeschlagen. Prüfe Jobbeschreibung." : "Failed to generate. Check your pasted job description.");
      }finally{
        refreshModeUi();
      }
    }


    /* -------------------------
       Description modal
       ------------------------- */
    async function openDescModal(){
      showError("");

      const jm = getActiveJobMeta();

      if(jobSource === "queue" && !selectedJob){
        showError(t("pickJob"));
        return;
      }

      H.showModal("descModal");
      $("descH").textContent = jm.title || (uiLang==="de" ? "Jobbeschreibung" : "Job description");

      const loc = (jobSource === "queue" && selectedJob) ? formatLoc(selectedJob) : "";
      $("descMeta").textContent = [jm.company_name || "", loc].filter(Boolean).join(" · ");

      $("descText").textContent = uiLang==="de" ? "Lade…" : "Loading…";
      $("descOpen").setAttribute("href", "#");
      $("descCopy").textContent = t("copy");
      selectedDesc = "";
      selectedApplyUrl = applyUrlSafe(jm.apply_url);

      if(selectedApplyUrl){
        $("descOpen").setAttribute("href", selectedApplyUrl);
        $("descOpen").classList.remove("ghost");
      }else{
        $("descOpen").setAttribute("href", "#");
        $("descOpen").classList.add("ghost");
      }

      // Paste mode: show pasted text immediately (no API call)
      if(jobSource === "paste"){
        const txt = getPasteDesc();
        selectedDesc = txt || (uiLang==="de" ? "(Keine Beschreibung eingefügt.)" : "(No description pasted.)");
        $("descText").textContent = selectedDesc;
        return;
      }

      try{
        const resp = await apiGet("/me/jobs/description?job_id=" + encodeURIComponent(String(selectedJob.id)));
        const job = resp?.job || null;
        const txt = String(job?.description_full || job?.description || "").trim();
        selectedDesc = txt || (uiLang==="de" ? "(Keine Beschreibung verfügbar.)" : "(No description available.)");
        $("descText").textContent = selectedDesc;
      }catch(e){
        $("descText").textContent = (uiLang==="de" ? "Beschreibung konnte nicht geladen werden." : "Failed to load description.") + "\n\n" + (e?.message || String(e));
      }
    }


    async function copyTextToClipboard(txt){
      const text = String(txt || "");
      if(!text) return;
      try{
        await navigator.clipboard.writeText(text);
      }catch(_){
        const ta = document.createElement("textarea");
        ta.value = text;
        document.body.appendChild(ta);
        ta.select();
        try{ document.execCommand("copy"); }catch{}
        document.body.removeChild(ta);
      }
    }

    async function copyDesc(){
      if(jobSource === "paste"){
        const d = getPasteDesc();
        if(!d) return;
        await copyTextToClipboard(d);
        return;
      }

      if(!selectedDesc){
        await openDescModal();
        return;
      }
      await copyTextToClipboard(selectedDesc);
    }

    /* -------------------------
       Copy / Download / Print
       ------------------------- */
    async function copyCv(){
      const txt = $("cvText").value || "";
      if(!txt.trim()) return;
      await copyTextToClipboard(txt);
      $("btnCopy").textContent = t("copied");
      setTimeout(()=>{ $("btnCopy").textContent = t("copy"); }, 900);
    }

    function downloadTxt(){
      const txt = $("cvText").value || "";
      if(!txt.trim()) return;

      const jm = getActiveJobMeta();
      const title = (jm?.title ? String(jm.title).slice(0, 60) : "tailored_cv");
      const safe = title.replace(/[^a-z0-9\-\_ ]/gi, "").trim().replace(/\s+/g, "_") || "tailored_cv";
      const filename = safe + ".txt";

      const blob = new Blob([txt], { type:"text/plain;charset=utf-8" });
      const url = URL.createObjectURL(blob);

      const a = document.createElement("a");
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    }

    function printPdf(){
      const jm = getActiveJobMeta();
      const jobTitle = jm?.title ? String(jm.title) : "Curriculum Vitae";
      const html = (lastCvDoc)
        ? cvDocToPrintableHtml(lastCvDoc, lastLang, jobTitle)
        : cvTextToPrintableHtml(jobTitle, $("cvText").value || "");
      printHtml(html);
    }


    /* -------------------------
       Final QA (local checks)
       ------------------------- */
    function currentCvHash(){
      return String(hashString($("cvText").value || ""));
    }

    function qaIsUpToDate(){
      if(!qaLastHash) return false;
      return qaLastHash === currentCvHash();
    }

    function updateQaDot(){
      const dot = $("qaDot");
      const btn = $("btnQa");
      if(!dot || !btn) return;

      if(btn.disabled){
        dot.style.display = "none";
        return;
      }
      dot.style.display = "";

      const up = qaIsUpToDate();
      const hasRun = !!qaLastRunAt;

      dot.className = "miniBadgeDot " + (up ? "good" : (hasRun ? "warn" : "bad"));
      dot.title = up
        ? (uiLang==="de" ? "QA aktuell" : "QA up to date")
        : (hasRun ? (uiLang==="de" ? "QA veraltet" : "QA out of date") : (uiLang==="de" ? "QA noch nicht ausgeführt" : "QA not run yet"));

      // Mirror status into the Inspector AI Review panel (if visible)
      const rb = $("reviewBadge");
      if(rb){
        rb.className = "badge " + (up ? "good" : (hasRun ? "warn" : "bad"));
        rb.textContent = up
          ? (uiLang==="de" ? "Aktuell" : "Up to date")
          : (hasRun ? (uiLang==="de" ? "Veraltet" : "Out of date") : (uiLang==="de" ? "Nicht gestartet" : "Not run"));
      }
    }

    function openQaModal(action){
      qaPendingAction = action || "";
      $("qaSummary").textContent = uiLang==="de" ? "Prüfe…" : "Checking…";
      $("qaMeta").textContent = "—";
      $("qaChecks").innerHTML = "";
      $("qaFixes").innerHTML = "";

      const cont = $("qaContinue");
      if(cont){
        if(qaPendingAction === "print"){
          cont.style.display = "";
          cont.textContent = uiLang==="de" ? "Weiter zu Print / PDF" : "Continue to Print / PDF";
        }else if(qaPendingAction === "download"){
          cont.style.display = "";
          cont.textContent = uiLang==="de" ? "Weiter zu Download" : "Continue to Download";
        }else{
          cont.style.display = "none";
        }
      }

      H.showModal("qaModal");
      runQaCheck();
    }

    function closeQaModal(){
      H.hideModal("qaModal");
      qaPendingAction = "";
      const cont = $("qaContinue");
      if(cont) cont.style.display = "none";
    }

    function guessLangFromText(text){
      const t = String(text || "").toLowerCase();
      // very small, robust stopword heuristic
      const de = [" und "," der "," die "," das "," mit "," für "," von "," als "," auf "," im "," in "," bei "," nicht "," wird "," wurden "," durch "," sowie "," ich "];
      const en = [" and "," the "," with "," for "," from "," as "," on "," in "," at "," not "," through "," including "," led "," built "," managed "];
      let deScore = 0, enScore = 0;
      de.forEach(w => { deScore += (t.split(w).length - 1); });
      en.forEach(w => { enScore += (t.split(w).length - 1); });
      if(deScore === 0 && enScore === 0) return "";
      if(deScore > enScore * 1.25) return "de";
      if(enScore > deScore * 1.25) return "en";
      return ""; // mixed/unclear
    }

    function qaComputeReport(){
      const text = String($("cvText").value || "");
      const doc = lastCvDoc || null;
      const targetLang = (lastLang || "").trim() || guessLangFromText(text) || "en";

      const checks = [];
      const fixes = [];

      function add(level, title, desc, fixId, fixLabel){
        checks.push({ level, title, desc: desc || "" });
        if(fixId){
          fixes.push({ fixId, title: fixLabel || title, desc: desc || "" });
        }
      }

      // 1) Basic presence
      const hasEmail = !!(doc?.contact?.email) || /[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i.test(text);
      if(!hasEmail){
        add("fix",
          uiLang==="de" ? "E-Mail fehlt" : "Email missing",
          uiLang==="de" ? "Füge eine E-Mail-Adresse hinzu. Ohne E-Mail ist die Bewerbung oft unvollständig." : "Add an email address. Without it, applications are often considered incomplete."
        );
      }else{
        add("pass",
          uiLang==="de" ? "Kontakt: E-Mail vorhanden" : "Contact: email present",
          uiLang==="de" ? "OK" : "OK"
        );
      }

      const hasExp = Array.isArray(doc?.experience) ? doc.experience.length > 0 : (text.toLowerCase().includes("experience") || text.toLowerCase().includes("erfahrung"));
      if(!hasExp){
        add("fix",
          uiLang==="de" ? "Erfahrung fehlt" : "Experience section missing",
          uiLang==="de" ? "Mindestens eine Station in EXPERIENCE/ERFAHRUNG ist nötig." : "You need at least one role in the EXPERIENCE section."
        );
      }else{
        add("pass",
          uiLang==="de" ? "Erfahrung vorhanden" : "Experience present",
          uiLang==="de" ? "OK" : "OK"
        );
      }

      // 2) Location sanity + common typo
      const loc = String(doc?.contact?.location || "");
      if(!loc && !/\b(Berlin|Germany|Deutschland|München|Hamburg|Köln|Frankfurt|Düsseldorf)\b/i.test(text)){
        add("warn",
          uiLang==="de" ? "Standort fehlt" : "Location missing",
          uiLang==="de" ? "Ein Standort erhöht Vertrauen und hilft beim Matching." : "A location improves trust and helps matching."
        );
      }
      if(/\bBelin\b/i.test(loc) || /\bBelin\b/i.test(text)){
        add("fix",
          uiLang==="de" ? "Tippfehler im Standort" : "Location typo detected",
          uiLang==="de" ? "„Belin“ sieht wie ein Tippfehler aus (meist „Berlin“)." : "“Belin” looks like a typo (usually “Berlin”).",
          "fix_location_berlin",
          uiLang==="de" ? "Belin → Berlin korrigieren" : "Fix Belin → Berlin"
        );
      }

      // 3) Language consistency
      const guess = guessLangFromText(text);
      if(guess && targetLang && guess !== targetLang){
        add("warn",
          uiLang==="de" ? "Sprache wirkt gemischt" : "Language may be mixed",
          uiLang==="de"
            ? ("Der Text wirkt eher " + (guess==="de" ? "Deutsch" : "Englisch") + ", aber das CV ist als " + (targetLang==="de" ? "Deutsch" : "Englisch") + " markiert.")
            : ("The text looks more " + (guess==="de" ? "German" : "English") + ", but the CV is marked as " + (targetLang==="de" ? "German" : "English") + ".")
        );
      }

      // 4) Bullet quality checks (if doc exists)
      if(doc && Array.isArray(doc.experience)){
        const longBullets = [];
        const allBullets = [];
        doc.experience.forEach((e, ei) => {
          const bullets = asStringArr(e?.bullets, 80);
          bullets.forEach((b, bi) => {
            const bb = String(b||"").trim();
            if(!bb) return;
            allBullets.push({ bb, ei, bi, title: e?.title || "" });
            const wc = bb.split(/\s+/).filter(Boolean).length;
            if(wc > 28 || bb.length > 220){
              longBullets.push({ bb, wc, ei, bi, title: e?.title || "" });
            }
          });
        });

        if(longBullets.length){
          const ex = longBullets.slice(0,2).map(x => `- ${x.title}: ${x.bb}`).join("\n");
          add("warn",
            uiLang==="de" ? "Zu lange Bullets" : "Bullets may be too long",
            uiLang==="de"
              ? ("Einige Bullets sind sehr lang. Kürzer = besser für ATS und Leser. Beispiele:\n" + ex)
              : ("Some bullets are very long. Shorter is better for ATS and readability. Examples:\n" + ex)
          );
        }else{
          add("pass",
            uiLang==="de" ? "Bullet-Länge ok" : "Bullet length OK",
            uiLang==="de" ? "OK" : "OK"
          );
        }

        // duplicates
        const seen = new Map();
        const dups = [];
        allBullets.forEach(x => {
          const key = normForMatch(x.bb).replace(/\d+/g,"#");
          if(!key) return;
          if(seen.has(key)){
            dups.push([seen.get(key), x]);
          }else{
            seen.set(key, x);
          }
        });
        if(dups.length){
          add("warn",
            uiLang==="de" ? "Doppelte Bullets" : "Duplicate bullets",
            uiLang==="de"
              ? ("Einige Bullets sind doppelt/nahezu gleich. Das wirkt repetitiv (ATS + Recruiter).")
              : ("Some bullets are duplicated or very similar. This looks repetitive (ATS + recruiter).")
          );
        }else{
          add("pass",
            uiLang==="de" ? "Keine Duplikate gefunden" : "No duplicates found",
            uiLang==="de" ? "OK" : "OK"
          );
        }

        // metrics
        const metricCount = allBullets.filter(x => /\d/.test(x.bb)).length;
        if(metricCount === 0){
          add("warn",
            uiLang==="de" ? "Wenig messbare Ergebnisse" : "Few measurable outcomes",
            uiLang==="de"
              ? "Keine Zahlen/Prozente gefunden. 1–3 messbare Ergebnisse erhöhen Glaubwürdigkeit."
              : "No numbers/percentages found. 1–3 measurable outcomes improve credibility."
          );
        }else{
          add("pass",
            uiLang==="de" ? "Ergebnisse mit Zahlen vorhanden" : "Metrics found",
            uiLang==="de" ? "OK" : "OK"
          );
        }

        // punctuation consistency (simple)
        const endPeriod = allBullets.filter(x => /[\.!?]$/.test(x.bb)).length;
        const ratio = allBullets.length ? (endPeriod / allBullets.length) : 0;
        if(allBullets.length >= 6 && ratio > 0.15 && ratio < 0.85){
          add("warn",
            uiLang==="de" ? "Punktuation inkonsistent" : "Punctuation inconsistent",
            uiLang==="de"
              ? "Einige Bullets enden mit Punkt, andere nicht. Einheitlich wirkt professioneller."
              : "Some bullets end with a period, others don’t. Consistency looks more professional.",
            "fix_bullet_punct",
            uiLang==="de" ? "Bullets ohne Punkt am Ende" : "Remove trailing periods"
          );
        }
      }

      // 5) Keyword coverage (from latest tailor call, if available)
      const miss = Array.isArray(lastMissing) ? lastMissing : [];
      if(miss.length){
        add("warn",
          uiLang==="de" ? "Fehlende Keywords" : "Missing keywords",
          uiLang==="de"
            ? ("Noch " + miss.length + " Keywords fehlen. Nutze den Keyword Booster, wenn sie wirklich zutreffen.")
            : (miss.length + " keywords are still missing. Use the Keyword Booster if they are true.")
        );
      }else if(lastUsed && Array.isArray(lastUsed)){
        add("pass",
          uiLang==="de" ? "Keywords abgedeckt" : "Keywords covered",
          uiLang==="de" ? "OK" : "OK"
        );
      }

      // Determine status
      const fixCount = checks.filter(c => c.level === "fix").length;
      const warnCount = checks.filter(c => c.level === "warn").length;
      const passCount = checks.filter(c => c.level === "pass").length;

      const status = fixCount ? "needs_fixes" : (warnCount ? "good_with_warnings" : "ready");
      return { status, targetLang, fixCount, warnCount, passCount, checks, fixes };
    }

    function renderQaReport(rep){
      if(!rep){ return; }

      const statusLine = (rep.status === "ready")
        ? (uiLang==="de" ? "Sieht gut aus – bereit zum Versand." : "Looks good — ready to send.")
        : (rep.status === "good_with_warnings")
          ? (uiLang==="de" ? "Gut – mit ein paar Verbesserungen." : "Good — with a few improvements.")
          : (uiLang==="de" ? "Bitte zuerst die wichtigsten Punkte fixen." : "Please fix the most important issues first.");

      $("qaSummary").textContent = statusLine;
      $("qaMeta").textContent = (uiLang==="de"
        ? (`Checks: ${rep.passCount} ok · ${rep.warnCount} Hinweise · ${rep.fixCount} Fixes · Sprache: ${rep.targetLang}`)
        : (`Checks: ${rep.passCount} ok · ${rep.warnCount} warnings · ${rep.fixCount} fixes · Language: ${rep.targetLang}`)
      );

      const checksEl = $("qaChecks");
      checksEl.innerHTML = rep.checks.map(c => {
        const tag = (c.level === "pass") ? (uiLang==="de" ? "OK" : "OK") : (c.level === "warn" ? (uiLang==="de" ? "Hinweis" : "Warning") : (uiLang==="de" ? "Fix" : "Fix"));
        const tagCls = (c.level === "pass") ? "good" : (c.level === "warn" ? "warn" : "bad");
        return `
          <div class="qaItem">
            <div class="qaHead">
              <div class="qaTitle">${H.escapeHtml(String(c.title||""))}</div>
              <span class="qaTag ${tagCls}">${H.escapeHtml(tag)}</span>
            </div>
            <div class="qaDesc">${H.escapeHtml(String(c.desc||""))}</div>
          </div>
        `;
      }).join("");

      const fixesEl = $("qaFixes");
      if(!rep.fixes.length){
        fixesEl.innerHTML = `<div class="qaItem"><div class="qaDesc">${uiLang==="de" ? "Keine Quick Fixes verfügbar." : "No quick fixes available."}</div></div>`;
      }else{
        fixesEl.innerHTML = rep.fixes.map(f => {
          return `
            <div class="qaItem">
              <div class="qaHead">
                <div class="qaTitle">${H.escapeHtml(String(f.title||""))}</div>
                <span class="qaTag warn">${uiLang==="de" ? "Quick Fix" : "Quick fix"}</span>
              </div>
              <div class="qaDesc">${H.escapeHtml(String(f.desc||""))}</div>
              <div class="qaActionsRow">
                <button class="btn small" type="button" data-fix="${H.escapeHtml(String(f.fixId||""))}">${uiLang==="de" ? "Anwenden" : "Apply"}</button>
              </div>
            </div>
          `;
        }).join("");
      }
    }

    function runQaCheck(){
      try{
        const rep = qaComputeReport();
        qaLastReport = rep;
        qaLastRunAt = Date.now();
        qaLastHash = currentCvHash();
        renderQaReport(rep);
        updateQaDot();
      }catch(e){
        $("qaSummary").textContent = (uiLang==="de" ? "QA fehlgeschlagen: " : "QA failed: ") + (e?.message || String(e));
        $("qaMeta").textContent = "—";
      }
    }

    function applyQaFix(fixId){
      if(!fixId) return;

      // Make sure Undo can bring us back
      try{ snapshotCurrent("QA fix: " + fixId); }catch(_){ }

      const txt0 = String($("cvText").value || "");
      let txt = txt0;

      if(fixId === "fix_location_berlin"){
        // Fix "Belin" typo in both structured doc (if any) and raw text
        try{
          if(lastCvDoc?.contact?.location){
            lastCvDoc.contact.location = String(lastCvDoc.contact.location).replace(/\bBelin\b/gi, "Berlin");
          }
        }catch(_){}
        txt = txt.replace(/\bBelin\b/gi, "Berlin");
      }

      if(fixId === "fix_bullet_punct"){
        // Remove trailing periods from bullets (simple heuristic)
        try{
          if(lastCvDoc && Array.isArray(lastCvDoc.experience)){
            lastCvDoc.experience = lastCvDoc.experience.map(e => {
              const bullets = asStringArr(e?.bullets, 80).map(b => String(b||"").replace(/[\s]*\.[\s]*$/,"").trim());
              return Object.assign({}, e, { bullets });
            });
          }
        }catch(_){}
        txt = txt.split("\n").map(line => {
          if(!/^\s*[-•]\s+/.test(line)) return line;
          return line.replace(/[\s]*\.[\s]*$/,"");
        }).join("\n");
      }

      if(txt !== txt0){
        $("cvText").value = txt;
        // If we have a structured doc, regenerate text from it for consistency
        try{
          if(lastCvDoc){
            $("cvText").value = cvDocToText(lastCvDoc, lastLang);
          }
        }catch(_){}
        recomputeCoverageFromCurrentText();
        if($("tabChanges")?.classList?.contains("active")){ try{ renderChangesView(); }catch(_){ } }
      }

      // QA needs rerun after changes
      try{ qaLastHash = ""; updateQaDot(); }catch(_){ }
      runQaCheck();
    }

    function onExportClick(kind){
      // If QA is not up to date, run it first and show results
      if(!qaIsUpToDate()){
        openQaModal(kind);
        return;
      }
      if(kind === "print") return printPdf();
      if(kind === "download") return downloadTxt();
    }

    async function copyMissing(){
      const miss = Array.isArray(lastMissing) ? lastMissing : [];
      if(!miss.length) return;
      const text = miss.map(k => prettyKeyword(k,lastLang)).join(", ");
      await copyTextToClipboard(text);
      $("btnCopyMissing").textContent = t("copied");
      setTimeout(()=>{ $("btnCopyMissing").textContent = t("copyMissing"); }, 900);
    }

    /* -------------------------
       Keyword booster (modal)
       ------------------------- */
    function setKwMode(mode){
      kwMode = mode === "quick" ? "quick" : "ai";
      const btns = $("kwModeToggle").querySelectorAll("button");
      btns.forEach(b => b.classList.toggle("active", b.getAttribute("data-mode") === kwMode));

      // Show/hide AI recommendation box
      const recoBox = $("kwAiRecoBox");
      if(recoBox) recoBox.style.display = (kwMode === "ai") ? "" : "none";

      // If user switches to AI while modal is open, refresh recommendation (non-blocking)
      if(kwMode === "ai" && activeKeywordRaw && lastCvDoc){
        const ready = (($("kwSkillGroup")?.options?.length || 0) > 0) || (($("kwExpRole")?.options?.length || 0) > 0);
        if(ready){
          try{ aiRecommendPlacement({ force:false, source:"mode" }); }catch(_){}
        }
      }

      try{ resetKwRewriteVariants(); updateKwRewriteUi(); }catch(_){ }
      updateKwPreview();
    }

    function chosenKwLang(){
      const v = String($("kwLang").value || "auto");
      if(v === "de" || v === "en") return v;
      // auto
      return isLikelyGerman(lastLang) ? "de" : "en";
    }

    function fillSkillGroups(){
      const sel = $("kwSkillGroup");
      sel.innerHTML = "";
      const groups = Array.isArray(lastCvDoc?.skills?.groups) ? lastCvDoc.skills.groups : [];
      groups.forEach((g, idx) => {
        const label = String(g?.label || "").trim() || (uiLang==="de" ? ("Gruppe " + (idx+1)) : ("Group " + (idx+1)));
        const opt = document.createElement("option");
        opt.value = "group:" + idx;
        opt.textContent = label;
        sel.appendChild(opt);
      });
      // additional bucket
      const opt2 = document.createElement("option");
      opt2.value = "additional";
      opt2.textContent = uiLang==="de" ? "Weitere Skills" : "Additional skills";
      sel.appendChild(opt2);

      if(sel.options.length) sel.value = sel.options[0].value;
    }

    function fillExperienceRoles(){
      const sel = $("kwExpRole");
      sel.innerHTML = "";
      const exp = Array.isArray(lastCvDoc?.experience) ? lastCvDoc.experience : [];
      exp.forEach((e, idx) => {
        const title = joinNonEmpty([e?.title, e?.company], " · ") || (uiLang==="de" ? ("Station " + (idx+1)) : ("Role " + (idx+1)));
        const opt = document.createElement("option");
        opt.value = String(idx);
        opt.textContent = title;
        sel.appendChild(opt);
      });
      if(sel.options.length) sel.value = "0";
      fillBulletsForSelectedRole();
    }

    function fillBulletsForSelectedRole(){
      const expIdx = Number($("kwExpRole").value || "0");
      const e = (Array.isArray(lastCvDoc?.experience) ? lastCvDoc.experience : [])[expIdx] || null;
      const bullets = asStringArr(e?.bullets, 50);

      const sel = $("kwExpBullet");
      sel.innerHTML = "";
      bullets.forEach((b, idx) => {
        const opt = document.createElement("option");
        opt.value = String(idx);
        opt.textContent = (String(b).length > 70 ? (String(b).slice(0,70) + "…") : String(b));
        sel.appendChild(opt);
      });

      if(sel.options.length){
        sel.value = "0";
        $("kwBulletPreview").textContent = bullets[0] || "—";
      }else{
        const opt = document.createElement("option");
        opt.value = "";
        opt.textContent = uiLang==="de" ? "Keine Bullets vorhanden" : "No bullets available";
        sel.appendChild(opt);
        $("kwBulletPreview").textContent = uiLang==="de" ? "Diese Station hat noch keine Bullets." : "This role has no bullets.";
      }
    }

    
    // -------------------------
    // AI recommendation (best placement)
    // -------------------------
    function clearKwAiReco(){
      kwAiReco = null;
      kwAiRecoKey = "";
      kwAiKeywordPretty = "";
      try{ setBadge("kwAiRecoBadge","", "—"); }catch(_){}
      try{ setText("kwAiRecoText", "—"); }catch(_){}
    }

    function setKwAiRecoLoading(){
      setBadge("kwAiRecoBadge","warn", uiLang==="de" ? "Denke…" : "Thinking…");
      setText("kwAiRecoText", uiLang==="de"
        ? "Finde das beste Placement und erstelle einen Vorschlag…"
        : "Finding the best placement and drafting a suggestion…"
      );
    }

    function setKwAiRecoError(msg){
      setBadge("kwAiRecoBadge","warn", uiLang==="de" ? "Nicht verfügbar" : "Unavailable");
      setText("kwAiRecoText", msg || (uiLang==="de"
        ? "Du kannst weiterhin Auto-pick oder Skills nutzen."
        : "You can still use Auto-pick or add it under Skills."
      ));
    }

    function slimCvDocForSuggest(doc){
      if(!doc || typeof doc !== "object") return null;

      const exp = Array.isArray(doc.experience) ? doc.experience : [];
      const expOut = exp.slice(0, 10).map((e) => ({
        title: String(e?.title || "").trim(),
        company: String(e?.company || "").trim(),
        bullets: asStringArr(e?.bullets, 10).map(b => String(b).trim().slice(0, 260))
      }));

      const skills = (doc.skills && typeof doc.skills === "object") ? doc.skills : {};
      const groups = Array.isArray(skills.groups) ? skills.groups : [];
      const groupsOut = groups.slice(0, 10).map((g) => ({
        label: String(g?.label || "").trim(),
        items: asStringArr(g?.items, 25).map(x => String(x).trim().slice(0, 80))
      }));

      const additionalOut = asStringArr(skills.additional, 60).map(x => String(x).trim().slice(0, 80));

      return { experience: expOut, skills: { groups: groupsOut, additional: additionalOut } };
    }

    function getAiRecoCacheKey(keyword, lang){
      const base = String(lastDebug?.input_hash || lastDebug?.hash || "");
      const src = String(jobSource || "queue");
      return [normForMatch(keyword), base, String(lang||""), src].join("|");
    }

    function roleLabelByIndex(expIdx){
      const e = (Array.isArray(lastCvDoc?.experience) ? lastCvDoc.experience : [])[Number(expIdx)||0] || null;
      return e ? (joinNonEmpty([e?.title, e?.company], " · ") || "") : "";
    }

    function skillGroupLabelByKey(groupKey){
      if(groupKey === "additional") return uiLang==="de" ? "Weitere Skills" : "Additional skills";
      const s = String(groupKey || "");
      if(s.startsWith("group:")){
        const idx = Number(s.split(":")[1] || "0");
        const g = (Array.isArray(lastCvDoc?.skills?.groups) ? lastCvDoc.skills.groups : [])[idx] || null;
        return String(g?.label || "").trim() || (uiLang==="de" ? ("Gruppe " + (idx+1)) : ("Group " + (idx+1)));
      }
      return uiLang==="de" ? "Skills" : "Skills";
    }

    function applyAiRecoToModalUi(reco){
      if(!reco) return;

      const target = String(reco.target || "").toLowerCase() === "experience" ? "experience" : "skills";
      $("kwTarget").value = target;
      updateKwTargetUi();

      if(target === "skills"){
        const sg = String(reco.skill_group || reco.skillGroup || "additional");
        if($("kwSkillGroup") && [...$("kwSkillGroup").options].some(o => o.value === sg)){
          $("kwSkillGroup").value = sg;
        }else{
          $("kwSkillGroup").value = "additional";
        }
      }else{
        const expIdx = Number(reco.exp_index ?? reco.expIdx ?? 0);
        const bulletIdx = Number(reco.bullet_index ?? reco.bulletIdx ?? 0);

        $("kwExpRole").value = String(Math.max(0, expIdx));
        fillBulletsForSelectedRole();

        if($("kwExpBullet") && [...$("kwExpBullet").options].some(o => o.value === String(bulletIdx))){
          $("kwExpBullet").value = String(bulletIdx);
        }else{
          $("kwExpBullet").value = "0";
        }

        $("kwExpHow").value = "rewrite";
        updateKwExpHowUi();

        const e = (Array.isArray(lastCvDoc?.experience) ? lastCvDoc.experience : [])[Number($("kwExpRole").value||0)] || null;
        const bullets = asStringArr(e?.bullets, 50);
        const i = Number($("kwExpBullet").value || "0");
        $("kwBulletPreview").textContent = bullets[i] || "—";
      }

      updateKwPreview();
    }

    function renderAiRecoBox(reco, lang){
      if(!reco){ clearKwAiReco(); return; }

      const conf = (typeof reco.confidence === "number") ? reco.confidence
        : (typeof reco.confidence_score === "number") ? reco.confidence_score
        : null;

      const confTxt = (conf != null && conf >= 0 && conf <= 1) ? (" • " + Math.round(conf*100) + "%") : "";
      setBadge("kwAiRecoBadge","good", (uiLang==="de" ? "Empfohlen" : "Recommended") + confTxt);

      const reason = String(reco.reason || "").trim();
      const target = String(reco.target || "").toLowerCase() === "experience" ? "experience" : "skills";

      if(target === "experience"){
        const expIdx = Number(reco.exp_index ?? reco.expIdx ?? 0);
        const bulletIdx = Number(reco.bullet_index ?? reco.bulletIdx ?? 0);
        const role = roleLabelByIndex(expIdx) || (uiLang==="de" ? "Experience" : "Experience");
        const rb = String(reco.rewritten_bullet || reco.rewrite || "").trim();

        const header = `Experience → ${role} (Bullet ${bulletIdx+1})`;
        const lines = [
          header,
          reason ? ("Reason: " + reason) : "",
          rb ? ("Suggested rewrite: " + rb) : ""
        ].filter(Boolean);

        setText("kwAiRecoText", lines.join("\n"));
      }else{
        const sg = String(reco.skill_group || reco.skillGroup || "additional");
        const groupLbl = skillGroupLabelByKey(sg);
        const item = String(reco.skill_item || reco.skillItem || prettyKeyword(activeKeywordRaw, lang)).trim();

        const header = `Skills → ${groupLbl}`;
        const lines = [
          header,
          reason ? ("Reason: " + reason) : "",
          item ? ("Suggested skill: " + item) : ""
        ].filter(Boolean);

        setText("kwAiRecoText", lines.join("\n"));
      }
    }

    async function tryAiSuggestPlacement({ keyword, lang, cv_doc, context }){
      const endpoints = [
        "/me/cv/keyword_suggest",
        "/me/cv/keyword_recommend"
      ];

      const payload = {
        keyword: String(keyword || ""),
        language: String(lang || ""),
        lang: String(lang || ""),
        cv_doc: cv_doc || null,
        context: context || {}
      };

      for(const ep of endpoints){
        try{
          const res = await apiPostJson(ep, payload);
          // expected: { ok:true, recommendation:{...}, keyword_pretty?:string }
          const keywordPretty = String(
            res?.keyword_pretty
              || res?.keywordPretty
              || res?.result?.keyword_pretty
              || res?.result?.keywordPretty
              || ""
          ).trim();

          const reco = res?.recommendation || res?.result?.recommendation || res?.result || res;
          if(reco && typeof reco === "object"){
            // Sometimes backend returns { recommendation:{...} } or a flat object
            const r = reco.recommendation || reco;
            if(r && (r.target || r.skill_group || r.exp_index != null)){
              return {
                ok: true,
                reco: r,
                endpoint: ep,
                keyword_pretty: keywordPretty,
                model: String(res?.model || res?.result?.model || ""),
                prompt_version: String(res?.prompt_version || res?.promptVersion || res?.result?.prompt_version || "")
              };
            }
          }
        }catch(e){
          if(isEndpointMissing(e)) continue;
          throw e;
        }
      }
      return { ok:false, reco:null, endpoint:"", keyword_pretty:"", model:"", prompt_version:"" };
    }

    async function aiRecommendPlacement({ force=false, source="auto" } = {}){
      if(!lastCvDoc || !activeKeywordRaw) return;
      if(kwMode !== "ai") return;

      const lang = chosenKwLang();
      const cacheKey = getAiRecoCacheKey(activeKeywordRaw, lang);
      kwAiRecoKey = cacheKey;

      // Cache hit
      if(!force && kwAiRecoCache.has(cacheKey)){
        const cached = kwAiRecoCache.get(cacheKey);
        kwAiReco = cached;
        kwAiKeywordPretty = String(cached?.keyword_pretty || "").trim();

        // If backend provided a nicer display, use it in the chip (does not change the raw keyword)
        if(kwAiKeywordPretty){
          activeKeywordDisplay = kwAiKeywordPretty;
          if($("kwChip")) $("kwChip").textContent = kwAiKeywordPretty;
        }

        applyAiRecoToModalUi(cached);
        renderAiRecoBox(cached, lang);
        try{ updateKwRewriteUi(); renderKwRewriteOptions(); }catch(_){ }
        return;
      }

      const token = ++kwAiRecoToken;
      setKwAiRecoLoading();

      try{
        const ctx = {
          target_language: lang,
          cv_language: lastLang,
          job: getActiveJobMeta(),
          source: source
        };

        const slim = slimCvDocForSuggest(lastCvDoc);
        const out = await tryAiSuggestPlacement({ keyword: activeKeywordRaw, lang, cv_doc: slim, context: ctx });

        if(token !== kwAiRecoToken) return; // stale

        if(out.ok && out.reco){
          const packed = Object.assign({}, out.reco);
          if(out.keyword_pretty) packed.keyword_pretty = out.keyword_pretty;

          kwAiReco = packed;
          kwAiKeywordPretty = String(out.keyword_pretty || packed.keyword_pretty || "").trim();
          kwAiRecoCache.set(cacheKey, packed);

          // If backend provided a nicer display, use it in the chip (does not change the raw keyword)
          if(kwAiKeywordPretty){
            activeKeywordDisplay = kwAiKeywordPretty;
            if($("kwChip")) $("kwChip").textContent = kwAiKeywordPretty;
          }

          applyAiRecoToModalUi(packed);
          renderAiRecoBox(packed, lang);
          try{ updateKwRewriteUi(); renderKwRewriteOptions(); }catch(_){ }
          updateKwPreview();
        }else{
          clearKwAiReco();
          setKwAiRecoError(uiLang==="de" ? "Keine Empfehlung verfügbar." : "No recommendation available.");
        }
      }catch(e){
        if(token !== kwAiRecoToken) return;
        clearKwAiReco();
        setKwAiRecoError((uiLang==="de" ? "AI Empfehlung fehlgeschlagen." : "AI recommendation failed.") + " " + (e?.message || String(e)));
      }
    }

function openKwModal(keywordRaw){
      showError("");
      if(!lastCvDoc && !($("cvText").value || "").trim()){
        showError(t("needCv"));
        return;
      }

      activeKeywordRaw = String(keywordRaw || "").trim();
      activeKeywordDisplay = prettyKeyword(activeKeywordRaw, lastLang);
      $("kwChip").textContent = activeKeywordDisplay || "—";
      $("kwTruth").checked = false;

      // Reset AI recommendation for this keyword
      try{ clearKwAiReco(); }catch(_){ }

      // Default language: auto (match CV language unless user overrides)
      $("kwLang").value = "auto";

      // Default mode: AI (best quality)
      setKwMode("ai");

      // Smart default target:
      // - Tool-like keywords (SQL/Excel/etc.) → Skills
      // - Otherwise → Experience (rewrite a bullet) if possible
      let recommendedTarget = "skills";
      if(lastCvDoc){
        recommendedTarget = isToolLikeKeyword(activeKeywordRaw) ? "skills" : "experience";
      }
      $("kwTarget").value = recommendedTarget;

      // Populate role/groups if doc available
      if(lastCvDoc){
        fillSkillGroups();
        fillExperienceRoles();

        // If we recommend Experience: auto-pick the best matching role + bullet
        if(recommendedTarget === "experience"){
          try{
            const best = pickBestRoleAndBullet(activeKeywordRaw);
            $("kwExpRole").value = String(best.expIdx || 0);
            fillBulletsForSelectedRole();
            $("kwExpBullet").value = String(best.bulletIdx || 0);
            // Update bullet preview text
            const e = (Array.isArray(lastCvDoc?.experience) ? lastCvDoc.experience : [])[Number(best.expIdx||0)] || null;
            const bullets = asStringArr(e?.bullets, 50);
            $("kwBulletPreview").textContent = bullets[Number(best.bulletIdx||0)] || "—";
            // Default experience action = rewrite (best)
            $("kwExpHow").value = "rewrite";
          }catch(_){}
        }
      }else{
        // if no doc, force skills box only (text-only)
        $("kwTarget").value = "skills";
      }

      // Show/hide boxes
      updateKwTargetUi();
      try{ updateKwRewriteUi(); resetKwRewriteVariants(); }catch(_){ }
      updateKwPreview();

      H.showModal("kwModal");

      // AI recommends best placement + draft rewrite (non-blocking)
      if(kwMode === "ai" && lastCvDoc){
        try{ aiRecommendPlacement({ force:false, source:"open" }); }catch(_){ }
      }
    }

    function closeKwModal(){
      H.hideModal("kwModal");
      activeKeywordRaw = "";
      activeKeywordDisplay = "";
      $("kwResultPreview").textContent = "—";
      $("kwNote").value = "";

      // Cancel any in-flight AI recommendation and reset UI
      try{ kwAiRecoToken += 1; }catch(_){ }
      try{ clearKwAiReco(); }catch(_){ }

      // Cancel/clear "Rewrite again" variants
      try{ kwRewriteToken += 1; }catch(_){ }
      kwRewriteVariants = [];
      kwRewriteSelected = "reco";
      kwRewriteKey = "";
      try{ updateKwRewriteUi(); }catch(_){ }
    }

    function updateKwTargetUi(){
      const target = String($("kwTarget").value || "skills");
      const hasDoc = !!lastCvDoc;

      $("kwSkillsBox").style.display = (target === "skills") ? "" : "none";
      $("kwExpBox").style.display = (target === "experience" && hasDoc) ? "" : "none";

      if(target === "experience" && !hasDoc){
        // can't do experience insert without doc
        $("kwTarget").value = "skills";
        $("kwSkillsBox").style.display = "";
        $("kwExpBox").style.display = "none";
      }

      updateKwExpHowUi();
    }

    function updateKwExpHowUi(){
      const how = String($("kwExpHow").value || "rewrite");
      const showPick = (how === "rewrite" || how === "append");
      $("kwBulletPickBox").style.display = showPick ? "" : "none";

      const showNote = (how === "new");
      $("kwNoteBox").style.display = showNote ? "" : "none";
      $("kwNewWarn").style.display = showNote ? "" : "none";

      // "Rewrite again" only makes sense when rewriting/appending an existing bullet in AI mode
      try{ updateKwRewriteUi(); }catch(_){ }

      updateKwPreview();
    }


    /* -------------------------
       Keyword modal: "Rewrite again" (variants)
       ------------------------- */
    function computeKwRewriteKey(){
      try{
        if(!activeKeywordRaw) return "";
        if(!lastCvDoc) return "";
        if(kwMode !== "ai") return "";
        const target = String($("kwTarget").value || "skills");
        if(target !== "experience") return "";
        const how = String($("kwExpHow").value || "rewrite");
        if(!(how === "rewrite" || how === "append")) return "";
        const expIdx = Number($("kwExpRole").value || "0");
        const bulletIdx = Number($("kwExpBullet").value || "0");
        const lang = chosenKwLang();
        return [String(activeKeywordRaw||""), String(lang||""), String(expIdx), String(bulletIdx), String(how)].join("||");
      }catch(_){
        return "";
      }
    }

    function getRecoRewriteForCurrentBullet(){
      try{
        const kw = activeKeywordRaw;
        const lang = chosenKwLang();
        const expIdx = Number($("kwExpRole").value || "0");
        const bulletIdx = Number($("kwExpBullet").value || "0");
        const key = getAiRecoCacheKey(kw, lang);

        if(kwMode === "ai" && kwAiReco && kwAiRecoKey === key && String(kwAiReco.target || "").toLowerCase() === "experience"){
          const reExp = Number(kwAiReco.exp_index ?? kwAiReco.expIdx ?? -1);
          const reBul = Number(kwAiReco.bullet_index ?? kwAiReco.bulletIdx ?? -1);
          const rb = String(kwAiReco.rewritten_bullet || kwAiReco.rewrite || "").trim();
          if(rb && reExp === expIdx && reBul === bulletIdx) return rb;
        }
      }catch(_){}
      return "";
    }

    function getCurrentSelectedBulletText(){
      try{
        const expIdx = Number($("kwExpRole").value || "0");
        const bulletIdx = Number($("kwExpBullet").value || "0");
        const exp = (Array.isArray(lastCvDoc?.experience) ? lastCvDoc.experience : [])[expIdx] || {};
        const bullets = asStringArr(exp?.bullets, 50);
        return String(bullets[bulletIdx] || "").trim();
      }catch(_){
        return "";
      }
    }

    function getDefaultRewriteDraftForCurrentBullet(){
      const lang = chosenKwLang();
      const kw = activeKeywordRaw;
      const how = String($("kwExpHow").value || "rewrite");
      const current = getCurrentSelectedBulletText();
      if(!current) return "";
      return (how === "append")
        ? localAppendKeyword(current, kw, lang)
        : localRewriteBullet(current, kw, lang);
    }

    function resetKwRewriteVariants(){
      kwRewriteVariants = [];
      kwRewriteSelected = "reco";
      kwRewriteKey = computeKwRewriteKey();
      renderKwRewriteOptions();
    }

    function setKwRewriteLoading(isLoading, msg){
      const badge = $("kwRewriteBadge");
      if(!badge) return;
      if(isLoading){
        badge.textContent = msg || (uiLang==="de" ? "Generiere…" : "Generating…");
        badge.className = "badge warn";
      }else{
        // badge updated in render
      }
    }

    function updateKwRewriteUi(){
      const box = $("kwRewriteBox");
      if(!box) return;

      const key = computeKwRewriteKey();
      const canShow = !!key;

      box.style.display = canShow ? "" : "none";

      if(!canShow){
        kwRewriteVariants = [];
        kwRewriteSelected = "reco";
        kwRewriteKey = "";
        const opt = $("kwRewriteOptions"); if(opt) opt.innerHTML = "";
        const badge = $("kwRewriteBadge"); if(badge){ badge.textContent = "—"; badge.className="badge"; }
        return;
      }

      if(key !== kwRewriteKey){
        kwRewriteKey = key;
        kwRewriteVariants = [];
        kwRewriteSelected = "reco";
      }

      renderKwRewriteOptions();
    }

    function renderKwRewriteOptions(){
      const box = $("kwRewriteBox");
      const list = $("kwRewriteOptions");
      const badge = $("kwRewriteBadge");
      if(!box || !list) return;

      const key = computeKwRewriteKey();
      if(!key || key !== kwRewriteKey){
        // keep it simple: reset when out-of-sync
        kwRewriteKey = key;
        kwRewriteVariants = [];
        kwRewriteSelected = "reco";
      }

      const reco = getRecoRewriteForCurrentBullet();
      const def = getDefaultRewriteDraftForCurrentBullet();
      const baseText = reco || def || "";

      // Badge
      if(badge){
        const n = kwRewriteVariants.length;
        badge.textContent = (n === 0) ? (uiLang==="de" ? "0 Varianten" : "0 variants") : (uiLang==="de" ? (n + " Varianten") : (n + " variants"));
        badge.className = "badge " + (n ? "good" : "warn");
      }

      // Build options
      const opts = [];
      opts.push({
        id: "reco",
        label: reco ? (uiLang==="de" ? "Empfohlen" : "Recommended") : (uiLang==="de" ? "Standard" : "Default"),
        pill: reco ? (uiLang==="de" ? "AI" : "AI") : (uiLang==="de" ? "Template" : "Template"),
        text: baseText || "—"
      });

      kwRewriteVariants.forEach((v, i) => {
        opts.push({
          id: "v:" + i,
          label: (uiLang==="de" ? "Variante " : "Variant ") + (i+1),
          pill: "AI",
          text: String(v?.text || "").trim() || "—"
        });
      });

      list.innerHTML = opts.map(o => {
        const active = (kwRewriteSelected === o.id) ? " active" : "";
        const safeText = H.escapeHtml(String(o.text||""));
        const safeLabel = H.escapeHtml(String(o.label||""));
        const safePill = H.escapeHtml(String(o.pill||""));
        return `
          <div class="altOption${active}" role="button" tabindex="0" data-alt="${safeLabel}" data-id="${H.escapeHtml(o.id)}">
            <div class="altMeta">
              <span class="altLabel">${safeLabel}</span>
              <span class="altPill">${safePill}</span>
            </div>
            <div class="altText">${safeText}</div>
          </div>
        `;
      }).join("");

      // If user selected a variant that no longer exists, fall back
      if(kwRewriteSelected !== "reco" && !opts.some(o => o.id === kwRewriteSelected)){
        kwRewriteSelected = "reco";
      }
    }

    function getPickedKwRewriteForCurrentBullet(){
      try{
        const key = computeKwRewriteKey();
        if(!key || key !== kwRewriteKey) return "";
        if(!kwRewriteSelected || kwRewriteSelected === "reco") return "";
        if(!String(kwRewriteSelected).startsWith("v:")) return "";
        const idx = Number(String(kwRewriteSelected).split(":")[1] || "-1");
        const v = kwRewriteVariants[idx];
        const text = String(v?.text || "").trim();
        return text || "";
      }catch(_){
        return "";
      }
    }

    async function onKwRewriteAgain(){
      showError("");
      if(!activeKeywordRaw){ return; }
      if(!lastCvDoc){ return; }
      if(kwMode !== "ai"){ return; }

      const key = computeKwRewriteKey();
      if(!key){
        showError(uiLang==="de" ? "Wähle zuerst eine Bullet aus." : "Please select a bullet first.");
        return;
      }
      if(key !== kwRewriteKey){
        resetKwRewriteVariants();
      }

      const lang = chosenKwLang();
      const kw = activeKeywordRaw;
      const how = String($("kwExpHow").value || "rewrite");
      const current = getCurrentSelectedBulletText();
      if(!current){
        showError(uiLang==="de" ? "Keine Bullet zum Umformulieren." : "No bullet to rewrite.");
        return;
      }

      const avoid = [];
      const reco = getRecoRewriteForCurrentBullet();
      if(reco) avoid.push(reco);
      kwRewriteVariants.forEach(v => { if(v?.text) avoid.push(String(v.text)); });

      const token = ++kwRewriteToken;
      setKwRewriteLoading(true);

      try{
        const expIdx = Number($("kwExpRole").value || "0");
        const exp = (Array.isArray(lastCvDoc?.experience) ? lastCvDoc.experience : [])[expIdx] || {};

        const ctx = {
          cv_language: lastLang,
          target_language: lang,
          role_title: exp?.title || "",
          company: exp?.company || "",
          job_title: selectedJob?.title || "",
          job_company: selectedJob?.company_name || "",
          intent: how,
          variation: kwRewriteVariants.length + 1,
          avoid_rewrites: avoid.slice(0, 6)
        };

        const ai = await tryAiRewriteOrCraft({
          mode: "rewrite",
          keyword: kw,
          lang,
          current_bullet: current,
          note: "",
          context: ctx
        });

        if(token !== kwRewriteToken) return;

        if(ai.ok && ai.text){
          const txt = String(ai.text || "").trim();
          const normTxt = normForMatch(txt);
          const exists = (
            normForMatch(getRecoRewriteForCurrentBullet()) === normTxt
            || kwRewriteVariants.some(v => normForMatch(v?.text||"") === normTxt)
          );
          if(!exists){
            kwRewriteVariants.push({ text: txt, at: Date.now() });
          }
          kwRewriteSelected = "v:" + Math.max(0, kwRewriteVariants.length - 1);
          renderKwRewriteOptions();
          updateKwPreview();
        }else{
          showError(t("aiFallback"));
        }
      }catch(e){
        showError((uiLang==="de" ? "Rewrite fehlgeschlagen: " : "Rewrite failed: ") + (e?.message || String(e)));
      }finally{
        setKwRewriteLoading(false);
      }
    }

    function buildKwPreviewText(){
      const target = String($("kwTarget").value || "skills");
      const lang = chosenKwLang();
      const kw = activeKeywordRaw;

      if(!kw) return "—";

      if(target === "skills"){
        const group = String($("kwSkillGroup").value || "additional");
        const dest = group === "additional"
          ? (uiLang==="de" ? "Weitere Skills" : "Additional skills")
          : ($("kwSkillGroup").selectedOptions?.[0]?.textContent || (uiLang==="de" ? "Skills" : "Skills"));

        // Prefer AI-prettified casing (e.g., "Power BI") when available for the same keyword+language
        let kwShow = prettyKeyword(kw, lang);
        try{
          const key = getAiRecoCacheKey(kw, lang);
          if(kwMode === "ai" && kwAiReco && kwAiRecoKey === key){
            const rTarget = String(kwAiReco.target || "").toLowerCase();
            if(rTarget === "skills"){
              const item = String(kwAiReco.skill_item || kwAiReco.skillItem || kwAiReco.keyword_pretty || kwAiKeywordPretty || "").trim();
              if(item) kwShow = item;
            }else{
              const pp = String(kwAiReco.keyword_pretty || kwAiKeywordPretty || "").trim();
              if(pp) kwShow = pp;
            }
          }
        }catch(_){}

        const verb = (lang==="de") ? "Füge hinzu:" : "Add:";
        return `${verb} ${kwShow} → ${dest}`;
      }

      // experience
      const expIdx = Number($("kwExpRole").value || "0");
      const exp = (Array.isArray(lastCvDoc?.experience) ? lastCvDoc.experience : [])[expIdx] || {};
      const roleName = joinNonEmpty([exp?.title, exp?.company], " · ") || (lang==="de" ? "Experience" : "Experience");
      const how = String($("kwExpHow").value || "rewrite");
      const bullets = asStringArr(exp?.bullets, 50);

      if(how === "new"){
        const note = $("kwNote").value || "";
        const b = (kwMode === "ai")
          ? localNewBullet(kw, note, lang) // AI preview might change, but good enough
          : localNewBullet(kw, note, lang);
        return (lang==="de")
          ? (`Neue Bullet bei ${roleName}:\n- ${b}`)
          : (`New bullet under ${roleName}:\n- ${b}`);
      }

      const bulletIdx = Number($("kwExpBullet").value || "0");
      const current = bullets[bulletIdx] || "";
      let rewritten = (how === "append")
        ? localAppendKeyword(current, kw, lang)
        : localRewriteBullet(current, kw, lang);

      // If we already have an AI recommendation for this exact bullet, show that draft (more accurate than templates)
      try{
        const key = getAiRecoCacheKey(kw, lang);
        if(kwMode === "ai" && kwAiReco && kwAiRecoKey === key && String(kwAiReco.target || "").toLowerCase() === "experience"){
          const reExp = Number(kwAiReco.exp_index ?? kwAiReco.expIdx ?? -1);
          const reBul = Number(kwAiReco.bullet_index ?? kwAiReco.bulletIdx ?? -1);
          const rb = String(kwAiReco.rewritten_bullet || kwAiReco.rewrite || "").trim();
          if(rb && reExp === expIdx && reBul === bulletIdx){
            rewritten = rb;
          }
        }
      }catch(_){}

      // If you generated alternative rewrites (Rewrite again), prefer the one you picked
      try{
        const picked = getPickedKwRewriteForCurrentBullet();
        if(picked) rewritten = picked;
      }catch(_){ }

      const label = (how === "append")
        ? (lang==="de" ? "Anhängen:" : "Append:")
        : (lang==="de" ? "Umformulieren:" : "Rewrite:");
      return `${label} ${roleName}\nALT: ${current}\nNEU: ${rewritten}`;
    }

    function updateKwPreview(){
      $("kwResultPreview").textContent = buildKwPreviewText();
    }

    async function applyKeyword(){
      showError("");
      if(!activeKeywordRaw){
        closeKwModal();
        return;
      }
      if(!$("kwTruth").checked){
        showError(t("truthRequired"));
        return;
      }

      const target = String($("kwTarget").value || "skills");
      const lang = chosenKwLang();
      const kwRaw = activeKeywordRaw;
      const kwDisp = prettyKeyword(kwRaw, lang);

      // Take history snapshot
      historyStack.push(snapshotCurrent());
      updateUndoResetButtons();

      try{
        if(target === "skills"){
          // Prefer AI-prettified casing for skills when available (saves a second AI call on Apply)
          let kwSkillAdd = kwDisp;
          try{
            const key = getAiRecoCacheKey(kwRaw, lang);
            if(kwMode === "ai" && kwAiReco && kwAiRecoKey === key){
              const rTarget = String(kwAiReco.target || "").toLowerCase();
              if(rTarget === "skills"){
                const item = String(kwAiReco.skill_item || kwAiReco.skillItem || kwAiReco.keyword_pretty || kwAiKeywordPretty || "").trim();
                if(item) kwSkillAdd = item;
              }else{
                const pp = String(kwAiReco.keyword_pretty || kwAiKeywordPretty || "").trim();
                if(pp) kwSkillAdd = pp;
              }
            }
          }catch(_){}

          if(!lastCvDoc){
            // text-only: just append to end as "Skills: ..."
            const txt = $("cvText").value || "";
            const addLine = (lang==="de") ? ("\nSKILLS\n" + kwSkillAdd + "\n") : ("\nSKILLS\n" + kwSkillAdd + "\n");
            $("cvText").value = (txt.trim() + "\n" + addLine).trim() + "\n";
          }else{
            const skillGroup = String($("kwSkillGroup").value || "additional");
            lastCvDoc.skills = lastCvDoc.skills || {};
            lastCvDoc.skills.groups = Array.isArray(lastCvDoc.skills.groups) ? lastCvDoc.skills.groups : [];
            lastCvDoc.skills.additional = Array.isArray(lastCvDoc.skills.additional) ? lastCvDoc.skills.additional : [];

            const ensureUniquePush = (arr, val) => {
              const exists = arr.some(x => normForMatch(x) === normForMatch(val));
              if(!exists) arr.push(val);
            };

            if(skillGroup.startsWith("group:")){
              const idx = Number(skillGroup.split(":")[1] || "0");
              const g = lastCvDoc.skills.groups[idx];
              if(g){
                g.items = Array.isArray(g.items) ? g.items : [];
                ensureUniquePush(g.items, kwSkillAdd);
              }else{
                ensureUniquePush(lastCvDoc.skills.additional, kwSkillAdd);
              }
            }else{
              ensureUniquePush(lastCvDoc.skills.additional, kwSkillAdd);
            }

            // Update text and preview
            $("cvPreview").innerHTML = cvDocToPreviewHtml(lastCvDoc, lastLang);
            $("cvText").value = cvDocToPlainText(lastCvDoc, lastLang);
          }

          recomputeCoverageFromCurrentText();
          try{ updateQaDot(); }catch(_){ }
          updateKwPreview();
          closeKwModal();
          return;
        }

        // Experience
        if(!lastCvDoc){
          showError(t("needDoc"));
          return;
        }

        const expIdx = Number($("kwExpRole").value || "0");
        const how = String($("kwExpHow").value || "rewrite");

        lastCvDoc.experience = Array.isArray(lastCvDoc.experience) ? lastCvDoc.experience : [];
        const exp = lastCvDoc.experience[expIdx];
        if(!exp){
          showError(t("needDoc"));
          return;
        }
        exp.bullets = Array.isArray(exp.bullets) ? exp.bullets : [];

        let changed = false;
        let usedAi = false;
        let aiNote = "";

        if(how === "new"){
          const note = String($("kwNote").value || "").trim();
          if(!note || note.length < 4){
            showError(t("noteRequired"));
            return;
          }

          if(kwMode === "ai"){
            const ctx = {
              cv_language: lastLang,
              target_language: lang,
              role_title: exp?.title || "",
              company: exp?.company || "",
              job_title: selectedJob?.title || "",
              job_company: selectedJob?.company_name || ""
            };
            const ai = await tryAiRewriteOrCraft({
              mode: "new",
              keyword: kwRaw,
              lang,
              current_bullet: "",
              note,
              context: ctx
            });
            if(ai.ok){
              exp.bullets.unshift(ai.text);
              usedAi = true;
            }else{
              aiNote = t("aiFallback");
              exp.bullets.unshift(localNewBullet(kwRaw, note, lang));
            }
          }else{
            exp.bullets.unshift(localNewBullet(kwRaw, note, lang));
          }
          changed = true;
        } else {
          const bulletIdx = Number($("kwExpBullet").value || "0");
          const current = String(exp.bullets[bulletIdx] || "").trim();
          if(!current){
            // If no bullets, degrade to new with required note
            const note = String($("kwNote").value || "").trim();
            exp.bullets.unshift(localNewBullet(kwRaw, note, lang));
            changed = true;
          }else{
            if(kwMode === "ai" && (how === "rewrite" || how === "append")){
              // If AI already suggested a rewrite for this exact bullet, use it (saves an extra AI call)
              const recoText = (kwAiReco
                && kwAiRecoKey === getAiRecoCacheKey(kwRaw, lang)
                && String(kwAiReco.target || "").toLowerCase() === "experience"
                && Number(kwAiReco.exp_index ?? kwAiReco.expIdx ?? -1) === expIdx
                && Number(kwAiReco.bullet_index ?? kwAiReco.bulletIdx ?? -1) === bulletIdx)
                  ? String(kwAiReco.rewritten_bullet || kwAiReco.rewrite || "").trim()
                  : "";

              // If you picked a specific rewrite variant (Rewrite again), use it first
              const picked = getPickedKwRewriteForCurrentBullet();
              if(picked){
                exp.bullets[bulletIdx] = picked;
                usedAi = true;
                changed = true;
              } else if(recoText){
                exp.bullets[bulletIdx] = recoText;
                usedAi = true;
                changed = true;
              }else{
              const ctx = {
                cv_language: lastLang,
                target_language: lang,
                role_title: exp?.title || "",
                company: exp?.company || "",
                job_title: selectedJob?.title || "",
                job_company: selectedJob?.company_name || "",
                intent: how
              };
              const ai = await tryAiRewriteOrCraft({
                mode: "rewrite",
                keyword: kwRaw,
                lang,
                current_bullet: current,
                note: "",
                context: ctx
              });
              if(ai.ok){
                exp.bullets[bulletIdx] = ai.text;
                usedAi = true;
                changed = true;
              }else{
                aiNote = t("aiFallback");
                exp.bullets[bulletIdx] = (how === "append")
                  ? localAppendKeyword(current, kwRaw, lang)
                  : localRewriteBullet(current, kwRaw, lang);
                changed = true;
              }
              }
            } else if(how === "append"){
              exp.bullets[bulletIdx] = localAppendKeyword(current, kwRaw, lang);
              changed = true;
            } else {
              exp.bullets[bulletIdx] = localRewriteBullet(current, kwRaw, lang);
              changed = true;
            }
          }
        }

        if(changed){
          $("cvPreview").innerHTML = cvDocToPreviewHtml(lastCvDoc, lastLang);
          $("cvText").value = cvDocToPlainText(lastCvDoc, lastLang);
          recomputeCoverageFromCurrentText();

          if(aiNote){
            // non-blocking: show as top info
            showError(aiNote);
          }
          closeKwModal();
        }
      }catch(e){
        // rollback snapshot
        const snap = historyStack.pop();
        restoreSnapshot(snap);
        showError(e?.message || String(e));
      }finally{
        updateUndoResetButtons();
        if($('tabChanges')?.classList?.contains('active')){ try{ renderChangesView(); }catch(_){ } }
        // Save edited output locally
        try{
          const key = "cvstudio_last_" + String(selectedJob?.id || "");
          localStorage.setItem(key, JSON.stringify({
            at: Date.now(),
            payload: buildTailorPayload(),
            cv_text: $("cvText").value || "",
            cv_doc: lastCvDoc,
            lang: lastLang,
            used: lastUsed,
            missing: lastMissing,
            all: atsKeywordsAll,
            debug: lastDebug
          }));
        }catch(_){}
      }
    }

    function undoEdit(){
      if(!historyStack.length) return;
      const snap = historyStack.pop();
      restoreSnapshot(snap);
      updateUndoResetButtons();
      if($("tabChanges")?.classList?.contains("active")){ try{ renderChangesView(); }catch(_){ } }
    }

    function resetEdits(){
      if(!baseSnapshot) return;
      historyStack = [];
      restoreSnapshot(baseSnapshot);
      updateUndoResetButtons();
      if($("tabChanges")?.classList?.contains("active")){ try{ renderChangesView(); }catch(_){ } }
    }

    /* -------------------------
       Auth + boot
       ------------------------- */
    async function loadStateAndNav(){
      setBadge("authBadge","warn", uiLang==="de" ? "Prüfe…" : "Checking…");

      const auth = getAppAuth();
      session = auth ? await auth.getSession() : null;
      try{ if(session && session.access_token) sessionStorage.setItem("sb_access_token", session.access_token); }catch(_){ }
      if(!session || !session.user || !session.user.email){
        setBadge("authBadge","warn", uiLang==="de" ? "Abgemeldet" : "Signed out");
        window.location.replace("./signup.html");
        return;
      }

      const navAcct = $("navAccount");
      if(navAcct) navAcct.style.display = "";
      $("navSignIn").style.display = "none";
      setBadge("authBadge","good", uiLang==="de" ? "Angemeldet" : "Signed in");

      // Ensure customer exists (best effort)
      try{
        await auth.requireAuthAndCustomer({ redirectTo: "./signup.html" });
      }catch(_){}

      try{
        await auth.syncStateToLocalStorage(session);
      }catch(_){}
    }

    async function boot(){
      showError("");

      applyUiTexts();
      applyStandaloneShell();
      setStrengthUi();

      // Step 1 Gate: if user didn't come from Jobs, start with job selection/paste as the main screen
      try{ setGateActive(shouldShowGate()); }catch(_){ }
      // If user clicked “Tailor in CV Studio” from Jobs, we arrive with ?job_id=...
      if(STANDALONE_MODE){
        incomingJobId = "";
      }else{
        try{
          incomingJobId = String(qs("job_id") || "").trim();
        }catch(_){
          incomingJobId = "";
        }
      }
      try{ setFromJobsUi(); }catch(_){}



      const auth = getAppAuth();
      if(!auth){
        showError("auth.js did not load. Ensure multipage/auth.js exists and is referenced as ./auth.js.");
        setBadge("authBadge","bad","Config error");
        return;
      }

      await loadStateAndNav();

      // restore saved template/strength
      try{
        const sv = localStorage.getItem("cv_strength");
        if(sv !== null && sv !== undefined && sv !== "") $("strengthRange").value = String(sv);
      }catch(_){}
      setStrengthUi();

      try{
        const tv = localStorage.getItem("cv_template");
        if(tv) $("tplSelect").value = tv;
      }catch(_){}
      setTemplateUi();

      // restore paste draft + job source (queue vs paste)
      loadJobSource();
      if(STANDALONE_MODE){
        try{ jobSource = "paste"; }catch(_){}
        try{ localStorage.setItem("cvstudio_job_source", "paste"); }catch(_){}
      }else if(incomingJobId){
        try{ jobSource = "queue"; }catch(_){}
        try{ localStorage.setItem("cvstudio_job_source", "queue"); }catch(_){}
      }

      loadPasteDraft();
      try{
        const extImport = consumeExtensionImport();
        if(extImport) applyExtensionImportToDraft(extImport);
      }catch(_){}
      applyPasteDraftToInputs();

      // apply initial mode UI
      setJobSource(jobSource);
      try{ updatePasteQuality(); }catch(_){}
      if(pendingExtensionImport){
        try{
          const host = pendingExtensionImport.source_host || "";
          const msg = host
            ? ("Imported job description from " + host + ". Review and click Generate.")
            : "Imported job description from your browser extension. Review and click Generate.";
          window.CVStudioShared?.toast?.(msg, { kind:"good", title:"CV Studio" });
          setText("jobHint", msg);
          $("settingsDetails").open = true;
        }catch(_){}
      }

      // Restore focus mode preference (Setup collapsed)
      // In Step 1 gate we always keep Setup visible.
      if(!gateActive){
        try{
          const c = localStorage.getItem("cvstudio_setup_collapsed");
          if(String(c||"") === "1") setSetupCollapsed(true, { persist:false, scroll:false });
        }catch(_){ }
      }else{
        setSetupCollapsed(false, { persist:false, scroll:false });
      }

      
      // Coming from Jobs: ensure Setup is visible (so the user sees template/strength first)
      if(incomingJobId){
        try{ setSetupCollapsed(false, { persist:false, scroll:false }); }catch(_){}
        setupUserToggled = true;
        try{ $("settingsDetails").open = true; }catch(_){}
      }

      if(!STANDALONE_MODE){
        await loadQueue();
        try{ armAutoStartFromJobs(); }catch(_){ }
      }

      try{ updateSourceChip(); }catch(_){}

      // initial output state
      renderKeywords();
      setTabs("preview");
      markSteps("idle");
      setOutputEnabled(false);
      updateUndoResetButtons();
    }

    /* -------------------------
       Wire UI
       ------------------------- */
    $("jobSelect").addEventListener("change", onJobChange);
// Setup panel collapse (focus mode)
$("btnCollapseSetup")?.addEventListener("click", () => {
  setupUserToggled = true;
  setSetupCollapsed(true);
});
$("btnShowSetup")?.addEventListener("click", () => {
  setupUserToggled = true;
  setSetupCollapsed(false, { scroll:false });
});

// “How it works” (steps) modal
$("btnHowItWorks")?.addEventListener("click", () => openGenModal(false));
$("genClose")?.addEventListener("click", closeGenModal);
$("genOk")?.addEventListener("click", closeGenModal);
$("genModal")?.addEventListener("click", (e) => { if(e.target && e.target.id === "genModal") closeGenModal(); });


    // Job source (queue vs paste)
    $("sourcePills").addEventListener("click", (e) => {
      const p = e.target.closest(".miniPill");
      if(!p) return;
      const src = String(p.getAttribute("data-src") || "queue");
      setJobSource(src);
    });

    // Pasted job description inputs
    ["pasteTitle","pasteCompany","pasteApply"].forEach((id) => {
      const el = $(id);
      if(!el) return;
      el.addEventListener("input", () => {
        savePasteDraft();
        refreshModeUi();
        try{ updateSourceChip(); }catch(_){}
      });
    });

    $("pasteLangHint").addEventListener("change", () => {
      savePasteDraft();
      updatePasteQuality();
    });

    $("pasteDesc").addEventListener("input", () => {
      savePasteDraft();
      updatePasteQuality();
      maybeAutoCollapseAfterPaste();
      try{ updateSourceChip(); }catch(_){}
    });

    $("strengthRange").addEventListener("input", setStrengthUi);
    $("strengthPills").addEventListener("click", (e) => {
      const p = e.target.closest(".miniPill");
      if(!p) return;
      $("strengthRange").value = String(p.getAttribute("data-s"));
      setStrengthUi();
    });

    $("tplSelect").addEventListener("change", setTemplateUi);

    $("btnAtsInfo").addEventListener("click", () => H.showModal("atsModal"));
    $("atsClose").addEventListener("click", () => H.hideModal("atsModal"));
    $("atsOk").addEventListener("click", () => H.hideModal("atsModal"));
    $("atsModal").addEventListener("click", (e) => { if(e.target && e.target.id === "atsModal") H.hideModal("atsModal"); });

    $("btnViewDesc").addEventListener("click", openDescModal);
    $("btnCopyDesc").addEventListener("click", async () => {
      try{
        await copyDesc();
        $("btnCopyDesc").textContent = t("copied");
        setTimeout(()=>{ $("btnCopyDesc").textContent = t("btnCopyDesc"); }, 900);
      }catch(_){}
    });

    $("descClose").addEventListener("click", () => H.hideModal("descModal"));
    $("descModal").addEventListener("click", (e) => { if(e.target && e.target.id === "descModal") H.hideModal("descModal"); });
    $("descCopy").addEventListener("click", async () => {
      if(!selectedDesc) return;
      await copyDesc();
      $("descCopy").textContent = t("copied");
      setTimeout(()=>{ $("descCopy").textContent = t("copy"); }, 900);
    });

    document.addEventListener("keydown", (e) => {
      if(e.key === "Escape"){
        H.hideModal("atsModal");
        H.hideModal("descModal");
        H.hideModal("kwModal");
        H.hideModal("qaModal");
        H.hideModal("activityModal");
        closeGenModal();
      }
    });

    $("btnGenerate").addEventListener("click", generate);
    $("btnGenerateAgain").addEventListener("click", generate);

    // “New CV” returns to Step 1 (chooser)
    $("btnNewCv")?.addEventListener("click", openGateForNewCv);

    // Auto-start controls (when arriving from Jobs)
    $("btnStartNow")?.addEventListener("click", async () => {
      clearAutoStartTimer();
      showAutoStartBar(false);
      try{ await generate(); }catch(_){}
    });
    $("btnCancelAuto")?.addEventListener("click", () => cancelAutoStart(true));


    // Step 1 chooser cards
    $("gatePickQueue")?.addEventListener("click", () => {
      try{ setJobSource("queue"); }catch(_){}
      setGateView("form");
      setTimeout(() => { try{ $("jobSelect")?.focus(); }catch(_){ } }, 60);
    });

    $("gatePickPaste")?.addEventListener("click", () => {
      try{ setJobSource("paste"); }catch(_){}
      setGateView("form");
      setTimeout(() => { try{ $("pasteDesc")?.focus(); }catch(_){ } }, 60);
    });

    // Back to the two-option chooser
    $("gateBackBtn")?.addEventListener("click", () => {
      setGateView("choose");
      setTimeout(() => { try{ $("gatePickQueue")?.focus(); }catch(_){ } }, 40);
    });


    
    // Studio mode buttons
    $("modeTailor")?.addEventListener("click", () => setStudioMode("tailor"));
    $("modeEdit")?.addEventListener("click", () => setStudioMode("edit"));
    $("modeReview")?.addEventListener("click", () => setStudioMode("review"));
    $("modeCustomize")?.addEventListener("click", () => setStudioMode("customize"));

    // Top-bar download menu hooks (reuse existing buttons)
    function closeStudioDownloadMenu(){
      const d = $("studioDownloadDrop");
      if(d) d.open = false;
    }
    $("studioActCopy")?.addEventListener("click", () => { closeStudioDownloadMenu(); $("btnCopy")?.click(); });
    $("studioActDownload")?.addEventListener("click", () => { closeStudioDownloadMenu(); $("btnDownload")?.click(); });
    $("studioActPrint")?.addEventListener("click", () => { closeStudioDownloadMenu(); $("btnPrint")?.click(); });
    $("studioActQa")?.addEventListener("click", () => { closeStudioDownloadMenu(); $("btnQa")?.click(); });

    // AI Review panel buttons
    $("btnRunReview")?.addEventListener("click", () => $("btnQa")?.click());
    $("btnOpenReview")?.addEventListener("click", () => $("btnQa")?.click());

    // Zoom controls (Preview)
    let zoom = 1.0;
    let zoomUserSet = false;
    let hadSavedZoom = false;

    function clamp(n, a, b){ return Math.max(a, Math.min(b, n)); }

    function computeFitZoom(){
      const stage = document.querySelector(".pageStage");
      const page = $("cvPreview");
      if(!stage || !page) return 1.0;

      const avail = Math.max(320, stage.clientWidth - 24);
      const base = page.offsetWidth || page.getBoundingClientRect().width || 0;
      if(!base) return 1.0;

      const z = avail / base;
      return clamp(z, 0.65, 1.35);
    }

    function applyZoom(persist = true){
      const z = $("pageZoom");
      if(z) z.style.transform = "scale(" + zoom.toFixed(2) + ")";
      const pct = $("zoomPct");
      if(pct) pct.textContent = Math.round(zoom * 100) + "%";
      if(persist){
        try { localStorage.setItem("jmj_cv_zoom", String(zoom)); } catch(_) {}
      }
    }

    try{
      const saved = Number(localStorage.getItem("jmj_cv_zoom") || "");
      if(saved && isFinite(saved)){
        zoom = clamp(saved, 0.55, 1.65);
        hadSavedZoom = true;
      }
    }catch(_){}

    if(!hadSavedZoom){
      zoom = computeFitZoom();
    }

    $("zoomIn")?.addEventListener("click", () => {
      zoomUserSet = true;
      zoom = clamp(zoom + 0.1, 0.55, 1.65);
      applyZoom(true);
    });
    $("zoomOut")?.addEventListener("click", () => {
      zoomUserSet = true;
      zoom = clamp(zoom - 0.1, 0.55, 1.65);
      applyZoom(true);
    });

    window.addEventListener("resize", () => {
      if(hadSavedZoom || zoomUserSet) return;
      zoom = computeFitZoom();
      applyZoom(false);
    });

    applyZoom(hadSavedZoom);
    $("zoomOut")?.addEventListener("click", () => { zoom = clamp(zoom - 0.1, 0.6, 1.4); applyZoom(); });
    applyZoom();

$("tabPreview").addEventListener("click", () => setTabs("preview"));
    $("tabText").addEventListener("click", () => setTabs("text"));
    $("tabChanges").addEventListener("click", () => setTabs("changes"));

    $("btnCopy").addEventListener("click", () => copyCv());
    $("btnDownload").addEventListener("click", () => onExportClick("download"));
    $("btnPrint").addEventListener("click", () => onExportClick("print"));
    $("btnQa").addEventListener("click", () => openQaModal(""));
    $("qaCloseX").addEventListener("click", closeQaModal);
    $("qaClose").addEventListener("click", closeQaModal);
    $("qaRunAgain").addEventListener("click", runQaCheck);
    $("qaContinue").addEventListener("click", () => {
      const kind = qaPendingAction;
      closeQaModal();
      if(kind === "print") return printPdf();
      if(kind === "download") return downloadTxt();
    });
    $("qaFixes").addEventListener("click", (e) => {
      const btn = e.target.closest("button[data-fix]");
      if(!btn) return;
      const fixId = btn.getAttribute("data-fix") || "";
      applyQaFix(fixId);
    });

    $("btnCopyMissing").addEventListener("click", copyMissing);

    // Track manual text edits -> recompute keyword coverage
    $("cvText").addEventListener("input", () => {
      // If user edits text manually, keep keywords in sync
      recomputeCoverageFromCurrentText();
      // We do not mutate doc here to avoid confusion; Preview stays as last doc.
      if($("tabChanges")?.classList?.contains("active")){ try{ renderChangesView(); }catch(_){ } }
      try{ updateQaDot(); }catch(_){ }
    });

    // Keyword chips click
    $("chipsMissing").addEventListener("click", (e) => {
      const btn = e.target.closest("button[data-kw]");
      if(!btn) return;
      const kw = btn.getAttribute("data-kw") || "";
      if(!kw) return;
      if(!lastCvDoc && !($("cvText").value||"").trim()){
        showError(t("needCv"));
        return;
      }
      openKwModal(kw);
    });

    // Undo / Reset
    $("btnUndoEdit").addEventListener("click", undoEdit);
    $("btnUndoFromChanges").addEventListener("click", () => { undoEdit(); renderChangesView(); });
    $("btnResetFromChanges").addEventListener("click", () => { resetEdits(); renderChangesView(); });
    $("btnCopyChangeSummary").addEventListener("click", copyChangeSummary);
    $("btnCopyDiff").addEventListener("click", copyDiffToClipboard);
    $("btnSyncTextToDoc").addEventListener("click", syncTextToPreview);

    // Change cards revert clicks (event delegation)
    $("changeCards").addEventListener("click", (e) => {
      const btn = e.target.closest("button[data-revert-id]");
      if(!btn) return;
      const id = btn.getAttribute("data-revert-id") || "";
      if(!id) return;
      revertStructuredChange(id);
    });

    $("btnResetEdits").addEventListener("click", resetEdits);

    // Keyword modal wiring
    $("kwClose").addEventListener("click", closeKwModal);
    $("kwCancel").addEventListener("click", closeKwModal);
    $("kwModal").addEventListener("click", (e) => { if(e.target && e.target.id === "kwModal") closeKwModal(); });

    $("kwTarget").addEventListener("change", () => { updateKwTargetUi(); try{ resetKwRewriteVariants(); updateKwRewriteUi(); }catch(_){ } updateKwPreview(); });
    $("kwLang").addEventListener("change", () => {
      try{ resetKwRewriteVariants(); updateKwRewriteUi(); }catch(_){ }
      updateKwPreview();
      if(kwMode === "ai" && activeKeywordRaw && lastCvDoc){
        try{ aiRecommendPlacement({ force:true, source:"lang" }); }catch(_){ }
      }
    });

    $("kwAiRecoRefresh").addEventListener("click", () => {
      if(kwMode === "ai" && activeKeywordRaw && lastCvDoc){
        try{ aiRecommendPlacement({ force:true, source:"refresh" }); }catch(_){ }
      }
    });

    $("kwModeToggle").addEventListener("click", (e) => {
      const b = e.target.closest("button[data-mode]");
      if(!b) return;
      setKwMode(b.getAttribute("data-mode"));
    });

    $("kwSkillGroup").addEventListener("change", updateKwPreview);
    $("kwExpRole").addEventListener("change", () => { fillBulletsForSelectedRole(); try{ resetKwRewriteVariants(); updateKwRewriteUi(); }catch(_){ } updateKwPreview(); });
    $("kwExpHow").addEventListener("change", updateKwExpHowUi);
    $("kwExpBullet").addEventListener("change", () => {
      const expIdx = Number($("kwExpRole").value || "0");
      const exp = (Array.isArray(lastCvDoc?.experience) ? lastCvDoc.experience : [])[expIdx] || null;
      const bullets = asStringArr(exp?.bullets, 50);
      const i = Number($("kwExpBullet").value || "0");
      $("kwBulletPreview").textContent = bullets[i] || "—";
      try{ resetKwRewriteVariants(); updateKwRewriteUi(); }catch(_){ }
      try{ resetKwRewriteVariants(); updateKwRewriteUi(); }catch(_){ }
      try{ resetKwRewriteVariants(); updateKwRewriteUi(); }catch(_){ }
      updateKwPreview();
    });
    
    $("kwAutoPick").addEventListener("click", () => {
      if(!lastCvDoc || !activeKeywordRaw) return;
      const best = pickBestRoleAndBullet(activeKeywordRaw);
      $("kwExpRole").value = String(best.expIdx || 0);
      fillBulletsForSelectedRole();
      $("kwExpBullet").value = String(best.bulletIdx || 0);
      const e = (Array.isArray(lastCvDoc?.experience) ? lastCvDoc.experience : [])[Number(best.expIdx||0)] || null;
      const bullets = asStringArr(e?.bullets, 50);
      $("kwBulletPreview").textContent = bullets[Number(best.bulletIdx||0)] || "—";
      const badge = $("kwAutoPickBadge");
      if(badge){
        badge.textContent = (best.score != null && best.score >= 0) ? ("Score " + best.score) : "—";
        badge.className = "badge " + ((best.score || 0) >= 4 ? "good" : "warn");
      }
      try{ resetKwRewriteVariants(); updateKwRewriteUi(); }catch(_){ }
      updateKwPreview();
    });
$("kwNote").addEventListener("input", updateKwPreview);
    
    $("kwRewriteAgain").addEventListener("click", onKwRewriteAgain);
    $("kwRewriteOptions").addEventListener("click", (e) => {
      const opt = e.target.closest(".altOption");
      if(!opt) return;
      const id = opt.getAttribute("data-id") || "reco";
      kwRewriteSelected = id;
      renderKwRewriteOptions();
      updateKwPreview();
    });
$("kwApply").addEventListener("click", applyKeyword);


    /* -------------------------
       Nav: Activity log modal
       ------------------------- */
    function activityBadge(type){
      const t = String(type || "").toLowerCase();
      if(t === "applied") return { cls:"good", label:"Applied" };
      if(t === "sent") return { cls:"good", label:"Sent" };
      if(t === "rejected") return { cls:"bad", label:"Rejected" };
      if(t === "skipped") return { cls:"warn", label:"Skipped" };
      if(t === "prioritized") return { cls:"prio", label:"Prioritized" };
      if(t === "queued") return { cls:"warn", label:"Queued" };
      if(t === "new") return { cls:"warn", label:"New" };
      return { cls:"", label:(type || "Event") };
    }

    function fmtWhen(ts){
      try{
        if(!ts) return "—";
        const d = new Date(ts);
        if(Number.isNaN(d.getTime())) return String(ts);
        return d.toLocaleString();
      }catch(_){
        return String(ts || "—");
      }
    }

    function renderActivityList(items, kind){
      const arr = Array.isArray(items) ? items : [];
      if(!arr.length){
        return '<span class="badge warn">No activity yet</span>';
      }

      const html = arr.slice(0, 20).map((row) => {
        const evType = kind === "applications" ? String(row.status || "new") : String(row.event_type || "");
        const b = activityBadge(evType);

        const job = (kind === "applications" ? (row.job || {}) : (row.job || {})) || {};
        const title = String(job.title || "Untitled");
        const company = String(job.company_name || job.company || "—");
        const loc = [job.city || "", job.region || ""].filter(Boolean).join(", ") || "—";
        const when = kind === "applications" ? (row.updated_at || row.created_at) : row.created_at;
        const link = job.apply_url ? String(job.apply_url) : "";
        const titleHtml = link
          ? ('<a href="'+H.escapeHtml(link)+'" target="_blank" rel="noopener">'+H.escapeHtml(title)+'</a>')
          : H.escapeHtml(title);

        let meta = "";
        try{
          if(kind !== "applications" && row.meta && typeof row.meta === "object"){
            if(row.meta.channel) meta = "via " + String(row.meta.channel);
            if(row.meta.reason_code) meta = meta ? (meta + " • reason: " + String(row.meta.reason_code)) : ("reason: " + String(row.meta.reason_code));
          }
        }catch(_){}

        return (
          '<div class="activityItem">' +
            '<div class="activityTop">' +
              '<div class="activityTitle">' + titleHtml + '</div>' +
              '<span class="badge ' + H.escapeHtml(b.cls) + '">' + H.escapeHtml(b.label) + '</span>' +
            '</div>' +
            '<div class="activityMeta">' +
              '<span>' + H.escapeHtml(company) + '</span>' +
              '<span>•</span>' +
              '<span>' + H.escapeHtml(loc) + '</span>' +
              '<span>•</span>' +
              '<span>' + H.escapeHtml(fmtWhen(when)) + '</span>' +
              (meta ? ('<span class="mono">• ' + H.escapeHtml(meta) + '</span>') : '') +
            '</div>' +
          '</div>'
        );
      }).join("");

      return '<div class="activityList">' + html + '</div>';
    }

    async function loadActivityLog(){
      H.showTopError("activityError", "");
      const wrap = $("activityWrap");
      if(wrap) wrap.innerHTML = '<div class="modalMonoBox">Loading…</div>';

      const token = session && session.access_token ? String(session.access_token) : "";
      if(!token){
        H.showTopError("activityError", "You are signed out. Please sign in again.");
        if(wrap) wrap.innerHTML = "";
        return;
      }

      const et = String($("activityFilter")?.value || "").trim();
      const headers = { Authorization: "Bearer " + token };

      // 1) Try timeline endpoint first
      try{
        let url = API_BASE + "/me/application-events?limit=20";
        if(et) url += "&event_type=" + encodeURIComponent(et);

        const res = await fetch(url, { method:"GET", headers });
        const text = await res.text().catch(()=> "");
        let json = null;
        try{ json = JSON.parse(text); }catch{ json = { raw: text }; }

        if(!res.ok){
          const msg = (json && (json.error || json.message)) ? String(json.error || json.message) : (text || ("HTTP " + res.status));
          throw new Error(msg);
        }

        const items = Array.isArray(json?.data) ? json.data : [];
        if(wrap) wrap.innerHTML = renderActivityList(items, "events");
        return;
      }catch(e){
        // fallback below
      }

      // 2) Fallback: applications list
      try{
        const map = { queued:"new", prioritized:"new", applied:"applied", rejected:"rejected", skipped:"skipped", sent:"applied" };
        let url = API_BASE + "/me/applications?limit=20";
        if(et && map[et]) url += "&status=" + encodeURIComponent(map[et]);

        const res = await fetch(url, { method:"GET", headers });
        const text = await res.text().catch(()=> "");
        let json = null;
        try{ json = JSON.parse(text); }catch{ json = { raw: text }; }

        if(!res.ok){
          const msg = (json && (json.error || json.message)) ? String(json.error || json.message) : (text || ("HTTP " + res.status));
          throw new Error(msg);
        }

        const items = Array.isArray(json?.data) ? json.data : [];
        if(wrap) wrap.innerHTML = renderActivityList(items, "applications");
      }catch(e){
        H.showTopError("activityError", e?.message || String(e));
        if(wrap) wrap.innerHTML = '<span class="badge bad">Activity failed</span>';
      }
    }

    function openActivityModal(){
      const dd = $("navAccount");
      if(dd) dd.open = false;
      H.showModal("activityModal");
      loadActivityLog().catch((e) => {
        H.showTopError("activityError", e?.message || String(e));
      });
    }

    function closeActivityModal(){
      H.hideModal("activityModal");
      H.showTopError("activityError", "");
    }


    // Activity modal wiring (available from the Account dropdown)
    $("navActivity")?.addEventListener("click", openActivityModal);
    $("activityCloseX")?.addEventListener("click", closeActivityModal);
    $("activityClose")?.addEventListener("click", closeActivityModal);
    $("activityModal")?.addEventListener("click", (e) => { if(e.target && e.target.id === "activityModal") closeActivityModal(); });
    $("activityRefresh")?.addEventListener("click", () => loadActivityLog().catch(()=>{}));
    $("activityFilter")?.addEventListener("change", () => loadActivityLog().catch(()=>{}));

    // Logout
    $("navLogout").addEventListener("click", async () => {
      try{
        const auth = getAppAuth();
        if(auth?.logout) await auth.logout("./index.html");
      }catch(_){
        window.location.href = "./index.html";
      }
    });

    // Initial view
    setTabs("preview");
    markSteps("idle");

    // Initial studio mode
    try{
      const savedMode = (localStorage.getItem("jmj_cv_mode") || "").trim();
      setStudioMode(savedMode || "tailor");
    }catch(_){
      setStudioMode("tailor");
    }


    window.addEventListener("load", () => {
      boot().catch((e) => {
        showError(e?.message || String(e));
        setBadge("authBadge","bad","Error");
      });
    });

  })();
  
