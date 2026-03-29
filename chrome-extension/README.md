# CV Studio Chrome Extension

This folder now contains a side-panel-first Chrome extension for `cvstudio.work`.

## What it does

- opens as a Chrome side panel
- scrapes the active job posting page
- uses cleaner platform-aware heuristics for LinkedIn, Greenhouse, Lever, Indeed, Workday, and generic career pages
- lets the user review or edit the scraped title, company, URL, and job description
- opens `https://cvstudio.work/extension-bridge.html` and continues into the existing paste-tailor flow

## Load it locally

1. Open `chrome://extensions`
2. Enable `Developer mode`
3. Click `Load unpacked`
4. Select [chrome-extension](/Users/viktor/app/products/cvstudio.work/chrome-extension)
5. Pin the extension and click the action icon on a job posting page

Chrome should open the side panel because the extension config uses the Side Panel API as its primary UI.

If Chrome asks for access to the current job site, click `Scrape current tab` in the panel and approve the one-time origin permission.

## Package for the Chrome Web Store

Run:

```bash
./package-extension.sh
```

This creates:

`dist/cvstudio-tailor-extension.zip`

## Store submission helpers

Supporting publication docs are in [store](/Users/viktor/app/products/cvstudio.work/chrome-extension/store):

- [listing.md](/Users/viktor/app/products/cvstudio.work/chrome-extension/store/listing.md)
- [privacy.md](/Users/viktor/app/products/cvstudio.work/chrome-extension/store/privacy.md)
- [test-instructions.md](/Users/viktor/app/products/cvstudio.work/chrome-extension/store/test-instructions.md)

## Limits

- The extension does not perform auth itself. It hands the job posting into `cvstudio.work`, which uses the existing Supabase session and stored CV.
- If the user is not signed in yet, the bridge page stores the imported payload on the `cvstudio.work` origin so the flow can continue after sign-in.
- Scraping is heuristic-based. Some heavily client-rendered or access-restricted job pages may still need manual cleanup.
