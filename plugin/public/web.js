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
  const handoff = document.getElementById('oidc-handoff');
  const mfa = document.getElementById('oidc-mfa');
  const progress = document.getElementById('oidc-progress');
  if (!handoff || !mfa || !progress) return;
  let busy = false;
  async function submit(event) {
    event.preventDefault();
    const form = event.currentTarget;
    if (busy || !form.reportValidity()) return;
    busy = true;
    const buttons = [...document.querySelectorAll('#oidc-signin button')];
    buttons.forEach(button => { button.disabled = true; });
    progress.textContent = 'Completing native sign-in…';
    let mayRetry = false;
    try {
      const body = new URLSearchParams(new FormData(form));
      const otp = mfa.querySelector('[name="otp"]');
      if (otp) otp.value = '';
      const response = await fetch(form.action, {method: 'POST', credentials: 'same-origin', redirect: 'error', cache: 'no-store', body, headers: {'Accept': 'application/json'}});
      const result = await response.json();
      if (!response.ok || result.ok !== true) {
        const code = result?.error?.code;
        mayRetry = form === mfa && code === 'MFA_INVALID';
        progress.textContent = code === 'MFA_INVALID' ? 'The authenticator code was not accepted. Try a current code.'
          : code === 'SIGN_OUT_OTHER_ACCOUNT' ? 'A different native account is already signed in. Sign out before starting again.'
          : 'Sign-in could not be completed. Start again or use native password login.';
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
      const checked = await fetch('/nms/api/v2.1/user/check-session', {method: 'POST', credentials: 'same-origin', redirect: 'error', cache: 'no-store', headers: {'x-auth-token': token}});
      if (checked.status !== 200) throw new Error('Native session check failed');
      localStorage.setItem('x-auth-token', token);
      progress.textContent = 'Signed in. Opening your native application…';
      location.assign(result.returnPath);
    } catch (_) {
      // Never log credentials, OTP, CSRF, request bodies, responses or exception text.
      progress.textContent = 'Sign-in could not be completed. Start again or use native password login.';
    } finally {
      busy = false;
      // An uncertain issuance consumes the attempt too. Only an explicit native
      // MFA challenge or rejected OTP permits another POST in this browser flow.
      if (mayRetry) buttons.forEach(button => { button.disabled = false; });
    }
  }
  handoff.addEventListener('submit', submit);
  mfa.addEventListener('submit', submit);
})();
