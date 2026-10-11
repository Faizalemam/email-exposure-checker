const APP_NAME = 'ITDelhi Email Exposure Checker';
const OTP_TTL_SECONDS = 600;
const OTP_COOLDOWN_SECONDS = 60;
const MAX_OTP_REQUESTS_PER_HOUR = 5;
const MAX_VERIFY_ATTEMPTS = 6;

function setupProject() {
  const props = PropertiesService.getScriptProperties();
  if (!props.getProperty('OTP_SECRET')) {
    props.setProperty('OTP_SECRET', Utilities.getUuid() + Utilities.getUuid());
  }
  Logger.log('Setup complete. Optional: add HIBP_API_KEY in Script Properties for breach checks.');
}

function doGet() {
  return json_({
    ok: true,
    service: APP_NAME,
    status: 'online',
    hibp_configured: Boolean(PropertiesService.getScriptProperties().getProperty('HIBP_API_KEY'))
  });
}

function doPost(e) {
  try {
    const body = parseBody_(e);
    const action = String(body.action || '').trim();

    if (action === 'request_otp') return requestOtp_(body);
    if (action === 'verify_and_scan') return verifyAndScan_(body);

    return json_({ ok: false, code: 'INVALID_ACTION', message: 'Unsupported action.' });
  } catch (err) {
    console.error(err);
    return json_({ ok: false, code: 'SERVER_ERROR', message: 'The secure checker could not complete this request.' });
  }
}

function requestOtp_(body) {
  const email = normalizeEmail_(body.email);
  if (!isValidEmail_(email)) return json_({ ok: false, code: 'INVALID_EMAIL', message: 'Enter a valid email address.' });
  if (body.consent !== true) return json_({ ok: false, code: 'CONSENT_REQUIRED', message: 'Ownership or authorization confirmation is required.' });

  const cache = CacheService.getScriptCache();
  const emailKey = digestHex_(email);
  const cooldownKey = 'cooldown:' + emailKey;
  const hourlyKey = 'hourly:' + emailKey;

  if (cache.get(cooldownKey)) {
    return json_({ ok: false, code: 'RATE_LIMIT', message: 'A verification code was sent recently. Please wait before requesting another.' });
  }

  const hourlyCount = Number(cache.get(hourlyKey) || 0);
  if (hourlyCount >= MAX_OTP_REQUESTS_PER_HOUR) {
    return json_({ ok: false, code: 'RATE_LIMIT', message: 'Too many verification requests. Try again later.' });
  }

  const otp = String(Math.floor(100000 + Math.random() * 900000));
  const secret = getOtpSecret_();
  const tokenHash = digestHex_(email + '|' + otp + '|' + secret);

  cache.put('otp:' + emailKey, tokenHash, OTP_TTL_SECONDS);
  cache.put('attempts:' + emailKey, '0', OTP_TTL_SECONDS);
  cache.put(cooldownKey, '1', OTP_COOLDOWN_SECONDS);
  cache.put(hourlyKey, String(hourlyCount + 1), 3600);

  MailApp.sendEmail({
    to: email,
    subject: APP_NAME + ' verification code',
    htmlBody: '<div style="font-family:Arial,sans-serif;max-width:520px;margin:auto;padding:24px">' +
      '<h2 style="margin:0 0 12px">Email verification</h2>' +
      '<p>Use this code to continue your exposure check:</p>' +
      '<div style="font-size:32px;font-weight:700;letter-spacing:8px;margin:24px 0">' + escapeHtml_(otp) + '</div>' +
      '<p>This code expires in 10 minutes. If you did not request it, you can ignore this email.</p>' +
      '<p style="color:#666;font-size:12px">' + APP_NAME + '</p></div>'
  });

  return json_({ ok: true, verification_required: true, expires_in: OTP_TTL_SECONDS });
}

function verifyAndScan_(body) {
  const email = normalizeEmail_(body.email);
  const code = String(body.code || '').trim();
  if (!isValidEmail_(email)) return json_({ ok: false, code: 'INVALID_EMAIL', message: 'Enter a valid email address.' });
  if (!/^\d{6}$/.test(code)) return json_({ ok: false, code: 'INVALID_CODE', message: 'Enter the 6-digit verification code.' });
  if (body.consent !== true) return json_({ ok: false, code: 'CONSENT_REQUIRED', message: 'Ownership or authorization confirmation is required.' });

  const cache = CacheService.getScriptCache();
  const emailKey = digestHex_(email);
  const otpKey = 'otp:' + emailKey;
  const attemptsKey = 'attempts:' + emailKey;
  const expected = cache.get(otpKey);

  if (!expected) return json_({ ok: false, code: 'CODE_EXPIRED', message: 'Verification code expired. Request a new code.' });

  const attempts = Number(cache.get(attemptsKey) || 0);
  if (attempts >= MAX_VERIFY_ATTEMPTS) {
    cache.remove(otpKey);
    return json_({ ok: false, code: 'TOO_MANY_ATTEMPTS', message: 'Too many incorrect attempts. Request a new code.' });
  }

  const actual = digestHex_(email + '|' + code + '|' + getOtpSecret_());
  if (actual !== expected) {
    cache.put(attemptsKey, String(attempts + 1), OTP_TTL_SECONDS);
    return json_({ ok: false, code: 'INVALID_CODE', message: 'Incorrect verification code.' });
  }

  cache.remove(otpKey);
  cache.remove(attemptsKey);
  return json_(scanVerifiedEmail_(email));
}

function scanVerifiedEmail_(email) {
  const domain = email.split('@')[1];
  const mx = dnsResolve_(domain, 'MX');
  const spf = dnsResolve_(domain, 'TXT').answers.some(function(v) { return /^v=spf1\b/i.test(v); });
  const dmarc = dnsResolve_('_dmarc.' + domain, 'TXT').answers.some(function(v) { return /^v=DMARC1\b/i.test(v); });
  const breach = lookupHibp_(email);

  let riskScore = null;
  let riskLabel = 'Breach API not configured';
  let summary = 'Email ownership was verified. Domain security checks completed.';

  if (breach.configured && breach.ok) {
    const count = breach.count;
    riskScore = count >= 5 ? 85 : count >= 2 ? 60 : count === 1 ? 35 : 10;
    riskLabel = count >= 5 ? 'High exposure' : count >= 2 ? 'Review recommended' : count === 1 ? 'Exposure found' : 'No breach found';
    summary = count > 0
      ? 'Verified breach records were found. Change reused passwords and enable 2FA on important accounts.'
      : 'No breach was returned by the configured provider. This does not guarantee the address has never been exposed.';
  }

  return {
    ok: true,
    verified: true,
    domain: domain,
    domain_security: {
      mx_found: mx.answers.length > 0,
      mx_records: mx.answers.slice(0, 10),
      spf_found: spf,
      dmarc_found: dmarc
    },
    breach_count: breach.configured && breach.ok ? breach.count : null,
    breach_names: breach.configured && breach.ok ? breach.names : [],
    breach_provider_configured: breach.configured,
    public_profiles: null,
    risk_score: riskScore,
    risk_label: riskLabel,
    summary: summary
  };
}

function lookupHibp_(email) {
  const key = PropertiesService.getScriptProperties().getProperty('HIBP_API_KEY');
  if (!key) return { configured: false, ok: false, count: null, names: [] };

  const url = 'https://haveibeenpwned.com/api/v3/breachedaccount/' + encodeURIComponent(email) + '?truncateResponse=false';
  const res = UrlFetchApp.fetch(url, {
    muteHttpExceptions: true,
    headers: {
      'hibp-api-key': key,
      'user-agent': 'ITDelhi-Email-Exposure-Checker/1.0'
    }
  });

  const status = res.getResponseCode();
  if (status === 404) return { configured: true, ok: true, count: 0, names: [] };
  if (status !== 200) return { configured: true, ok: false, count: null, names: [] };

  const rows = JSON.parse(res.getContentText() || '[]');
  const names = rows.map(function(row) { return String(row.Name || row.Title || 'Unknown'); }).slice(0, 25);
  return { configured: true, ok: true, count: rows.length, names: names };
}

function dnsResolve_(name, type) {
  try {
    const url = 'https://dns.google/resolve?name=' + encodeURIComponent(name) + '&type=' + encodeURIComponent(type);
    const res = UrlFetchApp.fetch(url, { muteHttpExceptions: true, headers: { accept: 'application/dns-json' } });
    if (res.getResponseCode() !== 200) return { answers: [] };
    const data = JSON.parse(res.getContentText() || '{}');
    const answers = (data.Answer || []).map(function(a) { return String(a.data || '').replace(/^"|"$/g, ''); });
    return { answers: answers };
  } catch (e) {
    return { answers: [] };
  }
}

function parseBody_(e) {
  if (!e || !e.postData || !e.postData.contents) return {};
  return JSON.parse(e.postData.contents);
}

function normalizeEmail_(value) {
  return String(value || '').trim().toLowerCase();
}

function isValidEmail_(email) {
  return email.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/i.test(email);
}

function getOtpSecret_() {
  const props = PropertiesService.getScriptProperties();
  let secret = props.getProperty('OTP_SECRET');
  if (!secret) {
    secret = Utilities.getUuid() + Utilities.getUuid();
    props.setProperty('OTP_SECRET', secret);
  }
  return secret;
}

function digestHex_(value) {
  const bytes = Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, value, Utilities.Charset.UTF_8);
  return bytes.map(function(b) { const v = (b < 0 ? b + 256 : b).toString(16); return v.length === 1 ? '0' + v : v; }).join('');
}

function escapeHtml_(value) {
  return String(value).replace(/[&<>"']/g, function(ch) {
    return ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[ch];
  });
}

function json_(obj) {
  return ContentService.createTextOutput(JSON.stringify(obj)).setMimeType(ContentService.MimeType.JSON);
}
