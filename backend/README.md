# Secure Google Apps Script backend

This backend verifies email ownership by OTP before running server-side checks.

## What it checks

- Email ownership via 6-digit OTP (10-minute expiry)
- MX records
- SPF record presence
- DMARC record presence
- Optional Have I Been Pwned breach lookup when `HIBP_API_KEY` is configured

It does **not** automate password-reset, forgot-password or account-recovery endpoints.

## Deploy

1. Create a new Google Apps Script project.
2. Copy `Code.gs` into the project.
3. In Project Settings, enable **Show appsscript.json manifest file in editor**, then replace the manifest with `appsscript.json` from this folder.
4. Run `setupProject()` once and approve the requested permissions.
5. Optional: Project Settings → Script Properties → add `HIBP_API_KEY` with your Have I Been Pwned API key.
6. Deploy → New deployment → Web app.
7. Execute as: **Me**.
8. Who has access: **Anyone**.
9. Copy the deployed `/exec` URL.
10. Paste that URL into `js/config.js` as `apiEndpoint`.

## Security notes

- OTP hashes are kept only in Apps Script cache and expire automatically.
- Do not put `HIBP_API_KEY` or other secrets into GitHub Pages files.
- OTP requests are rate-limited per email address.
- Real breach findings are shown only after the email OTP is verified.
