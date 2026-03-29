# Chrome Web Store Listing Draft

## Name

CV Studio Tailor

## Short description

Scrape the current job posting into CV Studio and tailor your saved CV to it.

## Detailed description

CV Studio Tailor opens a Chrome side panel that reads the current job posting, extracts the full job description, and sends it into `jobmejob.com`.

Inside CV Studio, the user can:
- reuse their already uploaded base CV
- review the scraped title, company, URL, and full job description
- generate a tailored CV using the existing backend flow
- export, print, or refine the tailored result

Supported best-effort scrapers:
- LinkedIn
- Greenhouse
- Lever
- Indeed
- Workday
- generic company career pages

## Single-purpose statement

This extension helps a signed-in CV Studio user tailor their existing CV to the currently open job posting.

## Permissions justification

- `activeTab`: scrape the page the user explicitly wants to tailor
- `scripting`: run the scraper on the active tab
- `tabs`: detect active tab changes while the side panel is open
- `sidePanel`: provide the main extension UI
- `contextMenus`: open the panel from the page context menu
- optional host permissions: request access to the current site only when scraping requires it

## Website

https://jobmejob.com/
