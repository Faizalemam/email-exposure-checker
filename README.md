# ITDelhi Email Exposure Checker

Privacy-first email exposure checking frontend.

## Status

Frontend v1 is included in this repository. Real breach / OSINT lookups must be performed by a secure backend so API keys and sensitive logic are never exposed in GitHub Pages JavaScript.

## Safety model

- Only scan email addresses you own or have permission to check.
- Do not automate account-recovery or password-reset endpoints to infer account existence.
- Keep API keys and credentials off the frontend.
- Do not store scanned email addresses unless the user explicitly opts in.

## Deployment

Serve this repository as a static site with GitHub Pages. When a backend is ready, set `API_ENDPOINT` in `js/app.js` to the secure HTTPS endpoint.
