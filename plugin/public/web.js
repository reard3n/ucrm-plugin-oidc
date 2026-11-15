'use strict';
(() => {
  const uuid = /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/;
  const safePath = value => {
    if (typeof value !== 'string' || value.length > 2048 || !/^\/(crm|nms)(\/|$)/.test(value)
      || /[\x00-\x20\x7f\\#]/.test(value) || /%(?:[01][0-9a-f]|7f|2f|5c|25|2e)/i.test(value)
      || value.includes('//') || /\/(login|logout|_plugins|api)([/? .]|$)/i.test(decodeURIComponent(value))) return false;
    return new URL(value, location.origin).origin === location.origin;
  };
  for (const form of document.querySelectorAll('form[data-confirm]')) {
    form.addEventListener('submit', event => { if (!window.confirm(form.dataset.confirm)) event.preventDefault(); });
  }
  const recovery = document.getElementById('oidc-login-recovery');
  const failed = (progress, message) => {
    progress.textContent = message;
    progress.dataset.failed = '1';
    if (recovery) recovery.hidden = false;
  };
  const restored = () => performance.getEntriesByType('navigation')[0]?.type === 'back_forward';
  const start = document.getElementById('oidc-start');
  if (start) {
    const progress = document.getElementById('oidc-start-progress');
    if (!progress || start.dataset.oidcInitialized === '1') return;
    start.dataset.oidcInitialized = '1';
    const failure = () => failed(progress, 'Sign-in could not start. Start sign-in again or use native password login.');
    window.addEventListener('pageshow', event => { if (event.persisted) failure(); });
    if (restored()) { failure(); return; }
    start.addEventListener('submit', event => {
      if (start.dataset.oidcSubmitted === '1') event.preventDefault();
      start.dataset.oidcSubmitted = '1';
    });
    // Keep the same-origin form POST and its CSRF/Origin checks. GET only
    // renders the browser-bound form; it never creates a provider transaction.
    window.setTimeout(failure, 15000);
    try { start.requestSubmit(); } catch (_) { failure(); }
    return;
  }
  const handoff = document.getElementById('oidc-handoff');
  const mfa = document.getElementById('oidc-mfa');
  const progress = document.getElementById('oidc-progress');
  if (!handoff || !mfa || !progress || handoff.dataset.oidcInitialized === '1') return;
  handoff.dataset.oidcInitialized = '1';
  let busy = false, handoffConsumed = false;
  const failure = message => failed(progress, message || 'Sign-in could not be completed. Start sign-in again or use native password login.');
  async function submit(form) {
    if (busy || (form === handoff && handoffConsumed) || !form.reportValidity()) return;
    if (form === handoff) handoffConsumed = true;
    busy = true;
    delete progress.dataset.failed;
    const buttons = [...document.querySelectorAll('#oidc-signin button')];
    buttons.forEach(button => { button.disabled = true; });
    progress.textContent = 'Completing native sign-in…';
    let mayRetry = false;
    const controller = new AbortController();
    const deadline = window.setTimeout(() => controller.abort(), 15000);
    try {
      const body = new URLSearchParams(new FormData(form));
      const otp = mfa.querySelector('[name="otp"]');
      if (otp) otp.value = '';
      const response = await fetch(form.action, {method: 'POST', credentials: 'same-origin', redirect: 'error', cache: 'no-store', signal: controller.signal, body, headers: {'Accept': 'application/json'}});
      const result = await response.json();
      if (!response.ok || result.ok !== true) {
        const code = result?.error?.code;
        mayRetry = form === mfa && code === 'MFA_INVALID';
        failure(code === 'MFA_INVALID' ? 'The authenticator code was not accepted. Try a current code.'
          : code === 'SIGN_OUT_OTHER_ACCOUNT' ? 'A different native account is already signed in. Use its native account menu to sign out, then start sign-in again.'
          : ['FLOW_EXPIRED', 'FLOW_USED', 'FLOW_INVALID', 'INVALID_FLOW', 'MFA_EXPIRED'].includes(code) ? 'This sign-in link has expired or has already been used. Start sign-in again.'
          : undefined);
        return;
      }
      if (result.kind === 'mfa') {
        mayRetry = true;
        handoff.hidden = true;
        mfa.hidden = false;
        progress.textContent = 'Enter the code from your native account authenticator.';
        otp?.focus();
        return;
      }
      const token = response.headers.get('x-auth-token');
      if (result.kind !== 'session' || !uuid.test(token || '') || !safePath(result.returnPath)) throw new Error('Invalid handoff');
      // This is the existing NMS artifact contract, not a plugin login session.
      const checked = await fetch('/nms/api/v2.1/user/check-session', {method: 'POST', credentials: 'same-origin', redirect: 'error', cache: 'no-store', signal: controller.signal, headers: {'x-auth-token': token}});
      if (checked.status !== 200) throw new Error('Native session check failed');
      localStorage.setItem('x-auth-token', token);
      progress.textContent = 'Signed in. Opening your native application…';
      location.assign(result.returnPath);
    } catch (_) {
      // Never log credentials, OTP, CSRF, request bodies, responses or exception text.
      failure();
    } finally {
      window.clearTimeout(deadline);
      busy = false;
      // An uncertain issuance consumes the attempt too. Only an explicit native
      // MFA challenge or rejected OTP permits another POST in this browser flow.
      if (mayRetry) buttons.forEach(button => { button.disabled = false; });
    }
  }
  for (const form of [handoff, mfa]) form.addEventListener('submit', event => { event.preventDefault(); void submit(form); });
  window.addEventListener('pageshow', event => { if (event.persisted) { handoffConsumed = true; failure('This sign-in page has already been opened. Start sign-in again.'); } });
  if (restored()) { handoffConsumed = true; failure('This sign-in page has already been opened. Start sign-in again.'); return; }
  if (handoff.dataset.autoHandoff === '1') void submit(handoff);
})();
