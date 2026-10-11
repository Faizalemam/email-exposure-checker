(() => {
  'use strict';

  // Set this to your secure HTTPS backend when it is ready, for example:
  // const API_ENDPOINT = 'https://api.example.com/v1/email-exposure/scan';
  // Never place private API keys in this frontend file.
  const API_ENDPOINT = '';

  const form = document.getElementById('scanForm');
  const emailInput = document.getElementById('email');
  const consentInput = document.getElementById('consent');
  const errorBox = document.getElementById('formError');
  const scanButton = document.getElementById('scanBtn');
  const results = document.getElementById('results');
  const newScanButton = document.getElementById('newScanBtn');
  const modeBadge = document.getElementById('modeBadge');

  const scoreRing = document.getElementById('scoreRing');
  const scoreValue = document.getElementById('scoreValue');
  const riskLabel = document.getElementById('riskLabel');
  const maskedEmail = document.getElementById('maskedEmail');
  const scoreNote = document.getElementById('scoreNote');
  const formatStatus = document.getElementById('formatStatus');
  const domainStatus = document.getElementById('domainStatus');
  const breachStatus = document.getElementById('breachStatus');
  const profileStatus = document.getElementById('profileStatus');

  if (!form) return;

  modeBadge.textContent = API_ENDPOINT ? 'Secure API' : 'Frontend demo';

  function normalizeEmail(value) {
    return value.trim().toLowerCase();
  }

  function isValidEmail(value) {
    if (value.length > 254) return false;
    return /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/i.test(value);
  }

  function getDomain(value) {
    const at = value.lastIndexOf('@');
    return at > -1 ? value.slice(at + 1) : '';
  }

  function maskEmail(value) {
    const [local, domain] = value.split('@');
    if (!local || !domain) return '—';
    const visible = local.length <= 2 ? local.slice(0, 1) : local.slice(0, 2);
    const stars = '*'.repeat(Math.max(3, Math.min(7, local.length - visible.length)));
    return `${visible}${stars}@${domain}`;
  }

  function setLoading(loading) {
    scanButton.disabled = loading;
    scanButton.querySelector('span:first-child').textContent = loading ? 'Checking securely…' : 'Check my exposure';
  }

  function markLocalChecks(email) {
    const domain = getDomain(email);
    formatStatus.textContent = 'Valid format';
    domainStatus.textContent = domain || 'Not detected';

    document.querySelectorAll('.scan-details .check-icon').forEach((icon, index) => {
      if (index < 2) {
        icon.classList.remove('neutral', 'warning');
        icon.classList.add('success');
        icon.textContent = '✓';
      }
    });
  }

  function renderDemo(email) {
    scoreRing.style.setProperty('--score', 0);
    scoreValue.textContent = '—';
    riskLabel.textContent = 'Exposure not scored';
    maskedEmail.textContent = maskEmail(email);
    scoreNote.textContent = 'Email format and domain were checked locally. A secure backend must be connected before breach or public-footprint findings can be reported.';
    breachStatus.textContent = 'Not queried — secure backend required';
    profileStatus.textContent = 'Not queried — secure backend required';
    markLocalChecks(email);
  }

  function clampScore(value) {
    const number = Number(value);
    if (!Number.isFinite(number)) return 0;
    return Math.max(0, Math.min(100, Math.round(number)));
  }

  function renderApiResult(email, data) {
    const score = clampScore(data.risk_score);
    const breachCount = Number.isFinite(Number(data.breach_count)) ? Number(data.breach_count) : null;
    const publicProfiles = Number.isFinite(Number(data.public_profiles)) ? Number(data.public_profiles) : null;

    scoreRing.style.setProperty('--score', score);
    scoreValue.textContent = String(score);
    riskLabel.textContent = data.risk_label || (score >= 70 ? 'High exposure' : score >= 35 ? 'Review recommended' : 'Lower exposure');
    maskedEmail.textContent = maskEmail(email);
    scoreNote.textContent = data.summary || 'Review the verified findings and recommended actions below.';
    breachStatus.textContent = breachCount === null ? 'No verified count returned' : `${breachCount} verified source${breachCount === 1 ? '' : 's'} reported`;
    profileStatus.textContent = publicProfiles === null ? 'No verified count returned' : `${publicProfiles} public profile${publicProfiles === 1 ? '' : 's'} reported`;
    markLocalChecks(email);
  }

  async function scanWithBackend(email) {
    const controller = new AbortController();
    const timeout = window.setTimeout(() => controller.abort(), 15000);

    try {
      const response = await fetch(API_ENDPOINT, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json'
        },
        body: JSON.stringify({ email, consent: true }),
        signal: controller.signal,
        credentials: 'omit',
        referrerPolicy: 'no-referrer'
      });

      if (!response.ok) {
        throw new Error(`Backend returned ${response.status}`);
      }

      const data = await response.json();
      if (!data || typeof data !== 'object') throw new Error('Invalid backend response');
      renderApiResult(email, data);
    } finally {
      window.clearTimeout(timeout);
    }
  }

  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    errorBox.textContent = '';

    const email = normalizeEmail(emailInput.value);
    emailInput.value = email;

    if (!isValidEmail(email)) {
      errorBox.textContent = 'Enter a valid email address.';
      emailInput.focus();
      return;
    }

    if (!consentInput.checked) {
      errorBox.textContent = 'Please confirm ownership or authorization before scanning.';
      consentInput.focus();
      return;
    }

    setLoading(true);

    try {
      if (API_ENDPOINT) {
        await scanWithBackend(email);
      } else {
        renderDemo(email);
      }

      results.hidden = false;
      results.scrollIntoView({ behavior: 'smooth', block: 'start' });
    } catch (error) {
      console.error(error);
      errorBox.textContent = error && error.name === 'AbortError'
        ? 'The secure checker timed out. Please try again.'
        : 'The secure checker could not complete this request. Please try again later.';
    } finally {
      setLoading(false);
    }
  });

  newScanButton?.addEventListener('click', () => {
    results.hidden = true;
    form.reset();
    errorBox.textContent = '';
    emailInput.focus();
    document.getElementById('scanner')?.scrollIntoView({ behavior: 'smooth', block: 'center' });
  });
})();
