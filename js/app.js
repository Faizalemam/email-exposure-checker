(() => {
  'use strict';

  const API_ENDPOINT = String(window.EMAIL_EXPOSURE_CONFIG?.apiEndpoint || '').trim();

  const form = document.getElementById('scanForm');
  const emailInput = document.getElementById('email');
  const consentInput = document.getElementById('consent');
  const scanButton = document.getElementById('scanBtn');
  const verifyButton = document.getElementById('verifyBtn');
  const otpPanel = document.getElementById('otpPanel');
  const otpInput = document.getElementById('otpCode');
  const errorBox = document.getElementById('formError');
  const successBox = document.getElementById('formSuccess');
  const results = document.getElementById('results');
  const newScanButton = document.getElementById('newScanBtn');
  const modeBadge = document.getElementById('modeBadge');
  const microcopy = document.getElementById('microcopy');

  const scoreRing = document.getElementById('scoreRing');
  const scoreValue = document.getElementById('scoreValue');
  const riskLabel = document.getElementById('riskLabel');
  const maskedEmail = document.getElementById('maskedEmail');
  const scoreNote = document.getElementById('scoreNote');
  const formatStatus = document.getElementById('formatStatus');
  const verifyStatus = document.getElementById('verifyStatus');
  const mxStatus = document.getElementById('mxStatus');
  const spfStatus = document.getElementById('spfStatus');
  const dmarcStatus = document.getElementById('dmarcStatus');
  const breachStatus = document.getElementById('breachStatus');
  const aiStatus = document.getElementById('aiStatus');
  const aiReportCard = document.getElementById('aiReportCard');
  const aiProviderLabel = document.getElementById('aiProviderLabel');
  const aiSummary = document.getElementById('aiSummary');
  const aiSourcesWrap = document.getElementById('aiSourcesWrap');
  const aiSources = document.getElementById('aiSources');

  if (!form) return;

  modeBadge.textContent = API_ENDPOINT ? 'Secure API' : 'Frontend demo';
  microcopy.textContent = API_ENDPOINT
    ? 'Ownership is verified by a 6-digit email code before DNS, breach-provider and AI public-web checks run.'
    : 'Safe local validation only. Connect the Apps Script /exec URL in js/config.js to enable OTP and real checks.';
  scanButton.querySelector('span:first-child').textContent = API_ENDPOINT ? 'Send verification code' : 'Check local validation';

  function normalizeEmail(value) {
    return value.trim().toLowerCase();
  }

  function isValidEmail(value) {
    return value.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/i.test(value);
  }

  function maskEmail(value) {
    const [local, domain] = value.split('@');
    if (!local || !domain) return '—';
    const visible = local.length <= 2 ? local.slice(0, 1) : local.slice(0, 2);
    return `${visible}${'*'.repeat(Math.max(3, Math.min(7, local.length - visible.length)))}@${domain}`;
  }

  function setIcon(id, state) {
    const icon = document.getElementById(id);
    if (!icon) return;
    icon.classList.remove('neutral', 'warning', 'success');
    if (state === true) {
      icon.classList.add('success');
      icon.textContent = '✓';
    } else if (state === false) {
      icon.classList.add('warning');
      icon.textContent = '!';
    } else {
      icon.classList.add('neutral');
      icon.textContent = 'i';
    }
  }

  function clearMessages() {
    errorBox.textContent = '';
    successBox.textContent = '';
  }

  function setButtonLoading(button, loading, loadingText, normalText) {
    if (!button) return;
    button.disabled = loading;
    button.querySelector('span:first-child').textContent = loading ? loadingText : normalText;
  }

  async function apiCall(payload) {
    const controller = new AbortController();
    const timeout = window.setTimeout(() => controller.abort(), 90000);
    try {
      const response = await fetch(API_ENDPOINT, {
        method: 'POST',
        headers: { 'Content-Type': 'text/plain;charset=UTF-8' },
        body: JSON.stringify(payload),
        signal: controller.signal,
        credentials: 'omit',
        referrerPolicy: 'no-referrer',
        redirect: 'follow'
      });
      const data = await response.json();
      if (!data || typeof data !== 'object') throw new Error('Invalid backend response');
      return data;
    } finally {
      window.clearTimeout(timeout);
    }
  }

  function resetAiReport() {
    if (aiReportCard) aiReportCard.hidden = true;
    if (aiProviderLabel) aiProviderLabel.textContent = 'AI Web Research';
    if (aiSummary) aiSummary.textContent = '';
    if (aiSources) aiSources.replaceChildren();
    if (aiSourcesWrap) aiSourcesWrap.hidden = true;
  }

  function renderAiReport(data) {
    resetAiReport();

    const provider = String(data.ai_provider || '').toLowerCase();
    const summary = String(data.ai_summary || '').trim();

    if (provider && summary) {
      if (provider === 'gemini') {
        aiStatus.textContent = 'Gemini grounded Google Search completed';
        if (aiProviderLabel) aiProviderLabel.textContent = 'Gemini + Google Search';
      } else if (provider === 'groq') {
        aiStatus.textContent = 'Groq Browser Search fallback completed';
        if (aiProviderLabel) aiProviderLabel.textContent = 'Groq Browser Search';
      } else {
        aiStatus.textContent = 'AI public-web research completed';
        if (aiProviderLabel) aiProviderLabel.textContent = 'AI Web Research';
      }

      setIcon('aiIcon', true);
      aiReportCard.hidden = false;
      aiSummary.textContent = summary;

      const sources = Array.isArray(data.ai_sources) ? data.ai_sources : [];
      if (sources.length) {
        sources.forEach((source, index) => {
          if (!source || !source.url) return;
          try {
            const a = document.createElement('a');
            a.href = source.url;
            a.target = '_blank';
            a.rel = 'noopener noreferrer';
            a.textContent = `${index + 1}. ${source.title || new URL(source.url).hostname}`;
            aiSources.appendChild(a);
          } catch (_) {}
        });
        aiSourcesWrap.hidden = aiSources.children.length === 0;
      }
      return;
    }

    const geminiConfigured = Boolean(data.gemini_configured);
    const groqConfigured = Boolean(data.groq_configured);
    const geminiStatus = Number(data.gemini_error_status || 0);
    const groqStatus = Number(data.groq_error_status || 0);

    if (!geminiConfigured && !groqConfigured) {
      aiStatus.textContent = 'No AI web-research API configured';
      setIcon('aiIcon', null);
      return;
    }

    if (geminiStatus === 429 && groqConfigured && !data.groq_ok) {
      aiStatus.textContent = groqStatus
        ? `Gemini quota exhausted; Groq fallback failed (HTTP ${groqStatus})`
        : 'Gemini quota exhausted; Groq fallback did not return a usable result';
      setIcon('aiIcon', false);
      return;
    }

    if (geminiStatus === 429 && !groqConfigured) {
      aiStatus.textContent = 'Gemini quota exhausted; Groq fallback not configured';
      setIcon('aiIcon', false);
      return;
    }

    if (groqConfigured && groqStatus) {
      aiStatus.textContent = `Groq web research failed (HTTP ${groqStatus})`;
      setIcon('aiIcon', false);
      return;
    }

    if (geminiConfigured && geminiStatus) {
      aiStatus.textContent = `Gemini web research failed (HTTP ${geminiStatus})`;
      setIcon('aiIcon', false);
      return;
    }

    aiStatus.textContent = 'AI research did not return a usable result';
    setIcon('aiIcon', false);
  }

  function renderDemo(email) {
    resetAiReport();
    scoreRing.style.setProperty('--score', 0);
    scoreValue.textContent = '—';
    riskLabel.textContent = 'Exposure not scored';
    maskedEmail.textContent = maskEmail(email);
    scoreNote.textContent = 'The email format was validated locally. Connect the secure backend to verify ownership and run server-side checks.';
    formatStatus.textContent = 'Valid format';
    verifyStatus.textContent = 'Backend not connected';
    mxStatus.textContent = 'Backend not connected';
    spfStatus.textContent = 'Backend not connected';
    dmarcStatus.textContent = 'Backend not connected';
    breachStatus.textContent = 'Breach provider not queried';
    aiStatus.textContent = 'Backend not connected';
    setIcon('formatIcon', true);
    setIcon('verifyIcon', null);
    setIcon('mxIcon', null);
    setIcon('spfIcon', null);
    setIcon('dmarcIcon', null);
    setIcon('breachIcon', null);
    setIcon('aiIcon', null);
  }

  function renderApiResult(email, data) {
    const hasScore = Number.isFinite(Number(data.risk_score));
    const score = hasScore ? Math.max(0, Math.min(100, Math.round(Number(data.risk_score)))) : 0;
    const domainSecurity = data.domain_security || {};
    const breachCount = data.breach_count === null || data.breach_count === undefined ? null : Number(data.breach_count);

    scoreRing.style.setProperty('--score', score);
    scoreValue.textContent = hasScore ? String(score) : '—';
    riskLabel.textContent = data.risk_label || (hasScore ? 'Scan complete' : 'Breach API not configured');
    maskedEmail.textContent = maskEmail(email);
    scoreNote.textContent = data.summary || 'Verified scan complete.';

    formatStatus.textContent = 'Valid format';
    verifyStatus.textContent = data.verified ? 'Verified by email OTP' : 'Not verified';
    mxStatus.textContent = domainSecurity.mx_found ? 'Mail exchanger records found' : 'No MX record detected';
    spfStatus.textContent = domainSecurity.spf_found ? 'SPF record found' : 'SPF record not detected';
    dmarcStatus.textContent = domainSecurity.dmarc_found ? 'DMARC record found' : 'DMARC record not detected';

    if (data.breach_provider_configured) {
      breachStatus.textContent = Number.isFinite(breachCount)
        ? `${breachCount} breach record${breachCount === 1 ? '' : 's'} returned by the configured provider`
        : 'Breach provider returned no usable result';
    } else {
      breachStatus.textContent = 'HIBP API key not configured';
    }

    setIcon('formatIcon', true);
    setIcon('verifyIcon', Boolean(data.verified));
    setIcon('mxIcon', Boolean(domainSecurity.mx_found));
    setIcon('spfIcon', Boolean(domainSecurity.spf_found));
    setIcon('dmarcIcon', Boolean(domainSecurity.dmarc_found));
    setIcon('breachIcon', data.breach_provider_configured && Number.isFinite(breachCount) ? breachCount === 0 : null);
    renderAiReport(data);
  }

  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    clearMessages();

    const email = normalizeEmail(emailInput.value);
    emailInput.value = email;

    if (!isValidEmail(email)) {
      errorBox.textContent = 'Enter a valid email address.';
      emailInput.focus();
      return;
    }
    if (!consentInput.checked) {
      errorBox.textContent = 'Please confirm ownership and authorize the security checks before continuing.';
      consentInput.focus();
      return;
    }

    if (!API_ENDPOINT) {
      renderDemo(email);
      results.hidden = false;
      results.scrollIntoView({ behavior: 'smooth', block: 'start' });
      return;
    }

    setButtonLoading(scanButton, true, 'Sending code…', 'Send verification code');
    try {
      const data = await apiCall({ action: 'request_otp', email, consent: true });
      if (!data.ok) throw new Error(data.message || 'Could not send verification code.');
      otpPanel.hidden = false;
      successBox.textContent = 'Verification code sent. Check your inbox and enter the 6-digit code.';
      scanButton.querySelector('span:first-child').textContent = 'Resend verification code';
      otpInput.focus();
    } catch (error) {
      errorBox.textContent = error.name === 'AbortError' ? 'The secure checker timed out.' : (error.message || 'Could not send verification code.');
    } finally {
      scanButton.disabled = false;
      if (!otpPanel.hidden) scanButton.querySelector('span:first-child').textContent = 'Resend verification code';
    }
  });

  verifyButton?.addEventListener('click', async () => {
    clearMessages();
    const email = normalizeEmail(emailInput.value);
    const code = String(otpInput.value || '').trim();

    if (!/^\d{6}$/.test(code)) {
      errorBox.textContent = 'Enter the 6-digit verification code.';
      otpInput.focus();
      return;
    }

    setButtonLoading(verifyButton, true, 'Verifying & researching…', 'Verify & scan');
    try {
      const data = await apiCall({ action: 'verify_and_scan', email, code, consent: true });
      if (!data.ok) throw new Error(data.message || 'Verification failed.');
      renderApiResult(email, data);

      if (data.ai_provider === 'groq') {
        successBox.textContent = 'Email verified. Security checks and Groq Browser Search research completed.';
      } else if (data.ai_provider === 'gemini') {
        successBox.textContent = 'Email verified. Security checks and Gemini grounded web research completed.';
      } else {
        successBox.textContent = 'Email verified and security scan completed.';
      }

      results.hidden = false;
      results.scrollIntoView({ behavior: 'smooth', block: 'start' });
    } catch (error) {
      errorBox.textContent = error.name === 'AbortError' ? 'The secure checker timed out.' : (error.message || 'Verification failed.');
    } finally {
      setButtonLoading(verifyButton, false, 'Verifying & researching…', 'Verify & scan');
    }
  });

  newScanButton?.addEventListener('click', () => {
    results.hidden = true;
    form.reset();
    otpPanel.hidden = true;
    resetAiReport();
    clearMessages();
    scanButton.querySelector('span:first-child').textContent = API_ENDPOINT ? 'Send verification code' : 'Check local validation';
    emailInput.focus();
    document.getElementById('scanner')?.scrollIntoView({ behavior: 'smooth', block: 'center' });
  });
})();
