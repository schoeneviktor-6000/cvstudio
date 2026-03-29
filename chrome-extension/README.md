# CV Studio Chrome Extension

This is an unpacked Chrome extension MVP for `cvstudio.work`.

What it does:
- scrapes the active job page
- extracts title, company, URL, and the main job description text
- opens `https://cvstudio.work/extension-bridge.html` with the extracted job data
- hands that data into the existing paste-tailor flow on `cvstudio.work`

## Load it locally

1. Open `chrome://extensions`
2. Enable `Developer mode`
3. Click `Load unpacked`
4. Select the folder [chrome-extension](/Users/viktor/app/products/cvstudio.work/chrome-extension)

## MVP limits

- The extension does not do auth itself. It hands the scraped job page into the website, and the website uses the existing Supabase session and stored CV.
- If the user is not signed in yet, the bridge stores the payload first so it can survive the redirect to sign-in.
- Scraping uses heuristics and prioritized selectors. It works best on job pages that render the description text into the DOM.
