export const MAX_DESCRIPTION_CHARS = 20000;
export const STUDIO_IMPORT_URL = "https://jobmejob.com/extension-bridge.html#import=";

export function truncateText(value, max){
  const text = String(value || "");
  if(text.length <= max) return text;
  return text.slice(0, Math.max(0, max - 1)) + "…";
}

export function base64UrlEncodeUtf8(value){
  const bytes = new TextEncoder().encode(String(value || ""));
  let binary = "";
  const chunkSize = 0x8000;
  for(let i = 0; i < bytes.length; i += chunkSize){
    binary += String.fromCharCode(...bytes.subarray(i, i + chunkSize));
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

export function buildStudioImportUrl(payload){
  const encoded = base64UrlEncodeUtf8(JSON.stringify(payload || {}));
  return STUDIO_IMPORT_URL + encodeURIComponent(encoded);
}

export function normalizeImportPayload(payload){
  const obj = payload && typeof payload === "object" ? payload : {};
  return {
    title: truncateText(String(obj.title || "").trim(), 180),
    company: truncateText(String(obj.company || "").trim(), 140),
    apply_url: String(obj.apply_url || obj.url || "").trim(),
    source_host: String(obj.source_host || "").trim(),
    language_hint: String(obj.language_hint || "auto").trim().toLowerCase() || "auto",
    description: String(obj.description || "").trim().slice(0, MAX_DESCRIPTION_CHARS),
    platform: String(obj.platform || "generic").trim(),
    page_title: String(obj.page_title || "").trim()
  };
}

export function scrapeJobPostingPage(){
  const host = String(window.location.hostname || "").trim().toLowerCase();
  const MAX_DESC = 20000;

  function truncateLocal(value, max){
    const text = String(value || "");
    if(text.length <= max) return text;
    return text.slice(0, Math.max(0, max - 1)) + "...";
  }

  function normalizePayloadLocal(payload){
    const obj = payload && typeof payload === "object" ? payload : {};
    return {
      title: truncateLocal(String(obj.title || "").trim(), 180),
      company: truncateLocal(String(obj.company || "").trim(), 140),
      apply_url: String(obj.apply_url || obj.url || "").trim(),
      source_host: String(obj.source_host || "").trim(),
      language_hint: String(obj.language_hint || "auto").trim().toLowerCase() || "auto",
      description: String(obj.description || "").trim().slice(0, MAX_DESC),
      platform: String(obj.platform || "generic").trim(),
      page_title: String(obj.page_title || "").trim()
    };
  }

  function allDocuments(){
    const docs = [document];
    const frames = document.querySelectorAll("iframe");
    for(const frame of frames){
      try{
        if(frame && frame.contentDocument && frame.contentDocument.documentElement){
          docs.push(frame.contentDocument);
        }
      }catch(_){}
    }
    return docs;
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

  function textFromNode(node){
    if(!node) return "";
    return normalizeExtractedText(node.innerText || node.textContent || "");
  }

  function stripHtml(html){
    return normalizeExtractedText(
      String(html || "")
        .replace(/<br\s*\/?>/gi, "\n")
        .replace(/<\/(p|div|li|ul|ol|h[1-6]|section|article)>/gi, "\n")
        .replace(/<[^>]+>/g, " ")
    );
  }

  function firstText(selectors){
    for(const doc of allDocuments()){
      for(const selector of selectors){
        const el = doc.querySelector(selector);
        if(!el) continue;
        const text = textFromNode(el);
        if(text) return text;
      }
    }
    return "";
  }

  function firstAttr(selectors, attr = "content"){
    for(const doc of allDocuments()){
      for(const selector of selectors){
        const el = doc.querySelector(selector);
        if(!el) continue;
        const value = String(el.getAttribute(attr) || "").trim();
        if(value) return value;
      }
    }
    return "";
  }

  function readJsonLdJobPosting(){
    for(const doc of allDocuments()){
      const scripts = doc.querySelectorAll("script[type='application/ld+json']");
      for(const script of scripts){
        const raw = String(script.textContent || "").trim();
        if(!raw) continue;
        try{
          const parsed = JSON.parse(raw);
          const queue = Array.isArray(parsed) ? [...parsed] : [parsed];

          while(queue.length){
            const item = queue.shift();
            if(!item || typeof item !== "object") continue;
            if(Array.isArray(item["@graph"])) queue.push(...item["@graph"]);

            const type = String(item["@type"] || "").toLowerCase();
            if(type !== "jobposting") continue;

            const company =
              String(item.hiringOrganization?.name || "").trim() ||
              String(item.organization?.name || "").trim();

            return {
              title: String(item.title || "").trim(),
              company,
              description: stripHtml(item.description || "")
            };
          }
        }catch(_){}
      }
    }

    return null;
  }

  function readLargestBlock(selectors, minChars = 120){
    const values = [];
    for(const doc of allDocuments()){
      for(const selector of selectors){
        const nodes = doc.querySelectorAll(selector);
        for(const node of nodes){
          const text = textFromNode(node);
          if(text.length >= minChars) values.push(text);
        }
      }
    }
    values.sort((a, b) => b.length - a.length);
    return values[0] || "";
  }

  function meta(selector, attr = "content"){
    return firstAttr([selector], attr);
  }

  function fallbackDescription(){
    const blocks = [];
    for(const doc of allDocuments()){
      const nodes = doc.querySelectorAll("section, article, main, div, [role='main']");
      for(const node of nodes){
        const text = textFromNode(node);
        if(text.length >= 300) blocks.push(text);
      }
    }

    blocks.sort((a, b) => b.length - a.length);
    if(blocks[0]) return blocks[0];

    for(const doc of allDocuments()){
      const rootText = normalizeExtractedText(
        (doc.body && (doc.body.innerText || doc.body.textContent)) ||
        (doc.documentElement && (doc.documentElement.innerText || doc.documentElement.textContent)) ||
        ""
      );
      if(rootText.length >= 120) return rootText;
    }

    return "";
  }

  function buildPayload(title, company, description, platform){
    const jsonLd = readJsonLdJobPosting() || {};
    const lang = String(document.documentElement.lang || "auto").split("-")[0] || "auto";
    return normalizePayloadLocal({
      title: title || jsonLd.title || meta("meta[property='og:title']") || String(document.title || "").replace(/\s+[|\-:]\s+.+$/, "").trim() || "Untitled role",
      company: company || jsonLd.company || meta("meta[property='og:site_name']"),
      apply_url: String(window.location.href || "").trim(),
      source_host: host,
      language_hint: lang,
      description: description || jsonLd.description || fallbackDescription(),
      platform,
      page_title: String(document.title || "").trim()
    });
  }

  function scrapeLinkedIn(){
    const title = firstText([
      ".job-details-jobs-unified-top-card__job-title",
      ".jobs-unified-top-card__job-title",
      ".jobs-search__job-details--container h1",
      ".jobs-search__job-details h1",
      ".scaffold-layout__detail h1",
      ".top-card-layout__title",
      "main h1",
      "h1"
    ]);

    const company = firstText([
      ".job-details-jobs-unified-top-card__company-name",
      ".jobs-unified-top-card__company-name",
      ".jobs-search__job-details--container a[href*='/company/']",
      ".jobs-search__job-details a[href*='/company/']",
      ".scaffold-layout__detail a[href*='/company/']",
      ".topcard__org-name-link",
      ".jobs-unified-top-card__subtitle-primary-grouping a",
      "a[href*='/company/']"
    ]);

    const description = readLargestBlock([
      ".jobs-description-content__text",
      ".jobs-box__html-content",
      ".show-more-less-html__markup",
      ".jobs-search__job-details--wrapper",
      ".jobs-search__job-details",
      ".jobs-details",
      ".job-details-module",
      ".scaffold-layout__detail",
      "[class*='jobs-description']",
      "[class*='job-details']",
      ".jobs-description__container",
      ".jobs-description"
    ], 100);

    return buildPayload(title, company, description, "linkedin");
  }

  function scrapeGreenhouse(){
    const title = firstText([
      ".app-title",
      ".job__title",
      "main h1",
      "h1"
    ]);
    const company = firstText([
      ".company-name",
      ".app-title + div"
    ]) || meta("meta[property='og:site_name']");
    const description = readLargestBlock([
      "#content",
      ".content",
      ".section-wrapper",
      "main"
    ], 200);
    return buildPayload(title, company, description, "greenhouse");
  }

  function scrapeLever(){
    const title = firstText([
      ".posting-headline h2",
      ".posting-headline h1",
      "main h1",
      "h1"
    ]);
    const company = firstText([
      ".main-header-text",
      ".posting-categories .sort-by-location"
    ]) || meta("meta[property='og:site_name']");
    const description = readLargestBlock([
      ".posting-page",
      ".section-wrapper",
      ".content",
      "main"
    ], 200);
    return buildPayload(title, company, description, "lever");
  }

  function scrapeIndeed(){
    const title = firstText([
      ".jobsearch-JobInfoHeader-title",
      "[data-testid='jobsearch-JobInfoHeader-title']",
      "main h1",
      "h1"
    ]);
    const company = firstText([
      "[data-testid='inlineHeader-companyName']",
      ".jobsearch-InlineCompanyRating div:first-child",
      ".icl-u-lg-mr--sm"
    ]);
    const description = readLargestBlock([
      "#jobDescriptionText",
      ".jobsearch-jobDescriptionText",
      ".jobsearch-JobComponent-description",
      "main"
    ], 180);
    return buildPayload(title, company, description, "indeed");
  }

  function scrapeWorkday(){
    const title = firstText([
      "[data-automation-id='jobPostingHeader'] h1",
      "[data-automation-id='jobPostingHeader']",
      "main h1",
      "h1"
    ]);
    const company = firstText([
      "[data-automation-id='companyName']",
      "[data-automation-id='company']"
    ]) || meta("meta[property='og:site_name']");
    const description = readLargestBlock([
      "[data-automation-id='jobPostingDescription']",
      "[data-automation-id='jobPostingDescription'] *",
      "main"
    ], 180);
    return buildPayload(title, company, description, "workday");
  }

  function scrapeGeneric(){
    const title = firstText([
      "[data-testid='job-title']",
      ".job-title",
      "main h1",
      "article h1",
      "h1"
    ]);
    const company = firstText([
      "[data-testid='company-name']",
      "[data-company-name]",
      ".company-name",
      ".company",
      ".employer"
    ]) || meta("meta[property='og:site_name']");
    const description = readLargestBlock([
      "[data-testid='job-details']",
      "[data-testid='jobDescriptionText']",
      "[data-test='job-description']",
      "[data-qa='job-description']",
      "[data-ui='job-description']",
      ".job-description",
      ".job-description-container",
      ".description",
      ".description__text",
      "main",
      "article",
      "[role='main']"
    ], 160);
    return buildPayload(title, company, description, "generic");
  }

  if(host.includes("linkedin.com")) return scrapeLinkedIn();
  if(host.includes("greenhouse.io")) return scrapeGreenhouse();
  if(host.includes("lever.co")) return scrapeLever();
  if(host.includes("indeed.")) return scrapeIndeed();
  if(host.includes("myworkdayjobs.com") || host.includes("workday.")) return scrapeWorkday();
  return scrapeGeneric();
}
