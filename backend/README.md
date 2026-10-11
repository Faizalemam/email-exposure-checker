# Secure Google Apps Script backend

This backend verifies email ownership by OTP before running server-side checks.

## What it checks

- Email ownership via 6-digit OTP (10-minute expiry)
- MX records
- SPF record presence
- DMARC record presence
- Optional Have I Been Pwned breach lookup when `HIBP_API_KEY` is configured
- Optional Gemini grounded public-web research when `GEMINI_API_KEY` is configured

Gemini uses Google Search grounding after OTP verification to research public web mentions and security-relevant exposure. It does **not** automate password-reset, forgot-password, login or account-recovery endpoints.

## Deploy

1. Create a new Google Apps Script project.
2. Copy `Code.gs` into the project.
3. In Project Settings, enable **Show appsscript.json manifest file in editor**, then replace the manifest with `appsscript.json` from this folder.
4. Run `setupProject()` once and approve the requested permissions.
5. Project Settings → Script Properties → add `GEMINI_API_KEY` with your Gemini API key.
6. Optional: add `HIBP_API_KEY` with your Have I Been Pwned API key.
7. Deploy → New deployment → Web app.
8. Execute as: **Me**.
9. Who has access: **Anyone**.
10. Copy the deployed `/exec` URL.
11. Paste that URL into `js/config.js` as `apiEndpoint`.

## Gemini behavior

- Model: `gemini-3.8-flash`
- Tool: Google Search grounding
- Searches happen only after the email OTP is verified.
- The prompt limits research to public-web cybersecurity/privacy findings.
- Returned grounded source URLs are displayed in the frontend.
- Results are cached for 30 minutes per verified email to reduce repeated AI/search costs.

## Security notes

- OTP hashes are kept only in Apps Script cache and expire automatically.
- Never put `GEMINI_API_KEY`, `HIBP_API_KEY`, or other secrets into GitHub Pages files.
- OTP requests are rate-limited per email address.
- Do not paste API keys into issues, commits, screenshots, or frontend JavaScript.
- Gemini research is public-web research only; no private/stolen credential sources or hidden-account inference are used.
