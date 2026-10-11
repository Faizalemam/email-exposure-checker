# ITDelhi Email Exposure Checker

Privacy-first email exposure checker with a GitHub Pages frontend and an optional Google Apps Script backend.

## Current status

- Responsive frontend: ready
- Email ownership OTP flow: ready
- Google Apps Script backend: ready
- MX / SPF / DMARC checks: ready
- Optional Have I Been Pwned integration: ready for API key
- Public-profile OSINT: intentionally not enabled in v1

## Architecture

- `index.html` — scanner and result dashboard
- `css/style.css` — responsive UI
- `js/config.js` — deployed backend URL only; no secrets
- `js/app.js` — OTP + scan client logic
- `backend/Code.gs` — OTP verification, DNS checks and optional breach lookup
- `backend/appsscript.json` — Apps Script manifest
- `backend/README.md` — backend deployment steps

## Safety model

- Real scans require control of the email inbox through a 6-digit OTP.
- Do not automate account-recovery or password-reset endpoints to infer account existence.
- API keys and credentials stay in backend Script Properties.
- OTP hashes are temporary and expire from cache.
- The frontend does not save scanned email addresses in localStorage or cookies.

## Deployment

1. Publish the repository frontend with GitHub Pages.
2. Deploy the code in `backend/` as a Google Apps Script Web App.
3. Copy the Apps Script `/exec` URL.
4. Put the URL in `js/config.js` as `apiEndpoint`.
5. Optionally add `HIBP_API_KEY` in Apps Script Script Properties for verified breach checks.

See `backend/README.md` for detailed backend instructions.
