(() => {
  'use strict';

  const cfg = window.EMAIL_EXPOSURE_CONFIG || {};
  const CX = String(cfg.googlePseCx || '').trim();
  if (!CX) return;

  const resultsGrid = document.querySelector('.results-grid');
  const resultsSection = document.getElementById('results');
  const verifyStatus = document.getElementById('verifyStatus');
  const emailInput = document.getElementById('email');
  const newScanBtn = document.getElementById('newScanBtn');
  if (!resultsGrid || !resultsSection || !verifyStatus || !emailInput) return;

  const style = document.createElement('style');
  style.textContent = `
    .google-search-card{grid-column:1/-1}
    .google-search-card .google-search-meta{margin:0 0 14px;color:#9fb2c5;font-size:12px;line-height:1.6}
    .google-search-card .gsc-control-cse{padding:0!important;border:0!important;background:transparent!important}
    .google-search-card .gsc-webResult.gsc-result{border-color:rgba(255,255,255,.08)!important;background:rgba(2,10,18,.34)!important;border-radius:12px!important;margin:8px 0!important;padding:12px!important}
    .google-search-card .gsc-result .gs-title,.google-search-card .gsc-result .gs-title *{color:#8de9e0!important}
    .google-search-card .gs-snippet{color:#b9c9d8!important}
    .google-search-card .gsc-url-top,.google-search-card .gsc-url-bottom{color:#7dd3fc!important}
    .google-search-card .gsc-adBlock{display:none!important}
  `;
  document.head.appendChild(style);

  const card = document.createElement('article');
  card.className = 'panel google-search-card';
  card.id = 'googleSearchCard';
  card.hidden = true;
  card.innerHTML = `
    <div class="ai-report-head">
      <div><span class="eyebrow">Google Programmable Search</span><h3>Google web results</h3></div>
      <span class="status-badge">Google Search</span>
    </div>
    <p class="google-search-meta" id="googleSearchStatus">Waiting for verified scan.</p>
    <div class="gcse-searchresults-only" data-gname="googleExposureSearch" data-linktarget="_blank" data-safeSearch="active"></div>
  `;
  resultsGrid.appendChild(card);

  const consentText = document.querySelector('.consent span');
  if (consentText) {
    consentText.textContent = 'I confirm I own this email address and authorize server-side security checks and public-web research. When configured, Google Programmable Search may also receive the verified address after OTP verification.';
  }

  const notice = document.querySelector('.notice-box');
  if (notice) {
    notice.innerHTML = '<strong>Important:</strong> Public-web research runs only after email ownership verification. Configured providers may include Gemini, Groq Browser Search and Google Programmable Search. The tool does not use password-reset/login probes, private databases, stolen credentials, or hidden-account inference.';
  }

  let scriptLoaded = false;
  let lastQueryEmail = '';

  function loadGoogleCse() {
    if (scriptLoaded) return;
    scriptLoaded = true;
    const script = document.createElement('script');
    script.async = true;
    script.src = 'https://cse.google.com/cse.js?cx=' + encodeURIComponent(CX);
    script.onerror = () => {
      const status = document.getElementById('googleSearchStatus');
      if (status) status.textContent = 'Google Programmable Search could not be loaded.';
    };
    document.head.appendChild(script);
  }

  function waitForElement(timeoutMs = 12000) {
    const started = Date.now();
    return new Promise((resolve) => {
      const tick = () => {
        const element = window.google?.search?.cse?.element?.getElement?.('googleExposureSearch');
        if (element) return resolve(element);
        if (Date.now() - started >= timeoutMs) return resolve(null);
        window.setTimeout(tick, 250);
      };
      tick();
    });
  }

  async function runGoogleSearch(email) {
    email = String(email || '').trim().toLowerCase();
    if (!email || email === lastQueryEmail) return;
    const domain = email.split('@')[1] || '';
    if (!domain) return;

    lastQueryEmail = email;
    card.hidden = false;
    const status = document.getElementById('googleSearchStatus');
    if (status) status.textContent = 'Searching Google for verified public-web mentions…';

    loadGoogleCse();
    const element = await waitForElement();
    if (!element) {
      if (status) status.textContent = 'Google Programmable Search is configured, but the search element did not initialize.';
      return;
    }

    const query = '"' + email + '" OR "' + domain + '"';
    try {
      element.execute(query);
      if (status) status.textContent = 'Google search completed for the verified address and domain. Review exact matches carefully.';
    } catch (err) {
      if (status) status.textContent = 'Google search could not be executed.';
    }
  }

  function maybeRun() {
    if (resultsSection.hidden) return;
    if (!/verified by email otp/i.test(String(verifyStatus.textContent || ''))) return;
    runGoogleSearch(emailInput.value);
  }

  const observer = new MutationObserver(maybeRun);
  observer.observe(resultsSection, { attributes: true, attributeFilter: ['hidden'] });
  observer.observe(verifyStatus, { childList: true, subtree: true, characterData: true });

  newScanBtn?.addEventListener('click', () => {
    lastQueryEmail = '';
    card.hidden = true;
    const status = document.getElementById('googleSearchStatus');
    if (status) status.textContent = 'Waiting for verified scan.';
  });
})();
