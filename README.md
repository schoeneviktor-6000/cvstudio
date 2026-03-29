# cvstudio.work Frontend

This repo is a focused spinout of the existing `jobmejob.com` frontend.

It keeps:
- Supabase Google sign-in
- CV upload and OCR bootstrap
- CV tailoring from pasted job descriptions
- Preview, ATS keyword inspection, copy/download/print actions

It intentionally drops the main `jobmejob` product surfaces such as jobs queue, dashboard, and plans from the primary user flow.

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

## Deployment

This is a static site meant for Cloudflare Pages.

Before deploying, replace the placeholder in [wrangler.toml.example](/Users/viktor/app/products/cvstudio.work/wrangler.toml.example) or download the Pages config from Cloudflare and save it as `wrangler.toml`.
