# cvstudio.work Frontend

This repo is a focused spinout of the existing `jobmejob.com` frontend.

It keeps:
- Supabase Google sign-in
- CV upload and OCR bootstrap
- CV tailoring from pasted job descriptions
- Preview, ATS keyword inspection, copy/download/print actions

It intentionally drops the main `jobmejob` product surfaces such as jobs queue, dashboard, and plans from the primary user flow.

## Chrome extension

This repo now also contains a side-panel Chrome extension at [chrome-extension](/Users/viktor/app/products/cvstudio.work/chrome-extension).

The extension flow is:
- scrape the active job posting page inside Chrome
- review and edit the scraped result in the side panel
- open `https://jobmejob.com/extension-bridge.html`
- store the extracted job payload in `jobmejob.com` localStorage
- continue into `jobmejob.com/cv.html` so the existing paste-tailor flow can use the user’s stored CV

This keeps the hard parts reused:
- existing Supabase sign-in
- existing uploaded/stored CV
- existing `/me/cv/tailor_from_text` path and exports

On first use for a new job site, the side panel may need a one-time origin permission. If so, click `Scrape current tab` and approve access for that site.

## Local preview

```bash
python3 -m http.server 8788
```

Then open [http://localhost:8788](http://localhost:8788).

## Shared backend reuse

The new frontend still points to the same:
- Supabase project: `https://awlzvhcnjegfhjedswko.supabase.co`
- Worker API base: `https://jobmejob.schoene-viktor.workers.dev`

To make `cvstudio.work` work with the same backend, update:
- Supabase Auth allowed redirect URLs to include `https://cvstudio.work/signup.html`
- Supabase Auth site URL if needed for your preferred default redirect
- Google OAuth / Supabase Google provider settings so the new domain is allowed
- Worker CORS allowlist so requests from `https://cvstudio.work` are accepted

For the Chrome extension in production, also verify:
- `https://jobmejob.com/extension-bridge.html` is deployed
- the extension opens the production domain, not localhost
- Chrome Web Store listing/privacy copy explains that job page text is sent into `jobmejob.com` for tailoring

## Deployment

This is a static site meant for Cloudflare Pages.

Before deploying, replace the placeholder in [wrangler.toml.example](/Users/viktor/app/products/cvstudio.work/wrangler.toml.example) or download the Pages config from Cloudflare and save it as `wrangler.toml`.
