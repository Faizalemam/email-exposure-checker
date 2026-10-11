# ITDelhi Email Exposure Checker

Privacy-first email exposure checker with a GitHub Pages frontend and Google Apps Script backend.

## Current status

- Responsive frontend: ready
- Email ownership OTP flow: ready
- Google Apps Script backend: ready
- MX / SPF / DMARC checks: ready
- Gemini + Google Search grounded public-web research: ready for `GEMINI_API_KEY`
- Optional Have I Been Pwned integration: ready for `HIBP_API_KEY`

## Architecture

- `index.html` — scanner and result dashboard
- `css/style.css` + `css/extra.css` — responsive UI, OTP and AI report styles
- `js/config.js` — deployed backend URL only; no secrets
- `js/app.js` — OTP + scan client logic and Gemini result rendering
- `backend/Code.gs` — OTP verification, DNS checks, optional HIBP lookup, Gemini grounded research
- `backend/appsscript.json` — Apps Script manifest
- `backend/README.md` — backend deployment steps

## Safety model

- Real scans require control of the email inbox through a 6-digit OTP.
- Gemini research runs only after OTP verification.
- Gemini is instructed to use public web sources only and not use password-reset/login/account-recovery probes, private credential databases, stolen secrets, or hidden-account inference.
- API keys and credentials stay in backend Script Properties.
- OTP hashes are temporary and expire from cache.
- The frontend does not save scanned email addresses in localStorage or cookies.

## Deployment

1. Publish the repository frontend with GitHub Pages.
2. Deploy the code in `backend/` as a Google Apps Script Web App.
3. Add `GEMINI_API_KEY` in Apps Script Script Properties.
4. Optionally add `HIBP_API_KEY` for verified breach-provider checks.
5. Copy the Apps Script `/exec` URL.
6. Put the URL in `js/config.js` as `apiEndpoint`.

See `backend/README.md` for detailed backend instructions.
