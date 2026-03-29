# Privacy Disclosure Draft

CV Studio Tailor reads the text of the current page only when the user opens the extension and requests a scrape.

Data handled:
- job title
- company name
- page URL
- visible job description text from the active page

Data destination:
- the extension opens `https://cvstudio.work` and passes the extracted job posting into the website
- CV tailoring happens on `cvstudio.work` using the user’s existing account and uploaded CV

The extension itself does not:
- run background scraping across tabs
- sell browsing data
- inject ads
- alter job websites

If the user is not signed in on `cvstudio.work`, the imported job data is held on the `cvstudio.work` origin so it can continue after sign-in.
