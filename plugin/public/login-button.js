'use strict';
(() => {
  const entry = '/crm/_plugins/ucrm-oidc/public.php';
  const id = 'ucrm-oidc-native-login';
  let pending = false;
  let queued = false;
  let metadata = null;
  let checkedAt = 0;
  const onLogin = () => /^\/nms\/login\/?$/.test(location.pathname);
  const remove = () => document.getElementById(id)?.remove();
  const returnPath = () => {
    const values = new URLSearchParams(location.search).getAll('returnurl');
    if (values.length !== 1) return '/nms/';
    const value = values[0];
    try {
      if (value.length > 2048 || !/^\/(crm|nms)(\/|$)/.test(value)
        || /[\x00-\x20\x7f\\#]/.test(value) || /%(?:[01][0-9a-f]|7f|2f|5c|25|2e)/i.test(value)
        || /(?:^|\/)\.{1,2}(?:\/|\?|$)/.test(value) || value.includes('//')) return '/nms/';
      const url = new URL(value, location.origin);
      const decodedPath = decodeURIComponent(url.pathname);
      if (url.origin !== location.origin || /[\x00-\x20\x7f\\%]/.test(decodedPath)
        || /\/(login|logout|_plugins|api)([/? .]|$)/i.test(decodedPath)) return '/nms/';
      return value;
    } catch (_) { return '/nms/'; }
  };
  async function refresh() {
    queued = false;
    if (!onLogin()) { remove(); return; }
    const password = document.querySelector('input[type="password"]');
    const form = password?.closest('form');
    if (!form) { remove(); return; }
    if (Date.now() - checkedAt > 15000) {
      if (pending) return;
      pending = true;
      checkedAt = Date.now();
      try {
        const response = await fetch(entry + '?action=status', {credentials: 'same-origin', cache: 'no-store', redirect: 'error', headers: {'Accept': 'application/json'}});
        metadata = response.ok ? await response.json() : null;
      } catch (_) { metadata = null; }
      finally { pending = false; }
    }
    // Awaiting metadata may span a SPA navigation or replace the original form.
    if (!onLogin() || !form.isConnected) { remove(); return; }
    if (metadata?.enabled !== true || metadata?.ready !== true || typeof metadata.loginLabel !== 'string' || metadata.loginLabel.length > 320) { remove(); return; }
    const href = entry + '?action=start&return=' + encodeURIComponent(returnPath());
    const existing = document.getElementById(id);
    if (existing) {
      const link = existing.querySelector('a');
      if (link.textContent !== metadata.loginLabel) link.textContent = metadata.loginLabel;
      if (link.getAttribute('href') !== href) link.setAttribute('href', href);
      return;
    }
    const block = document.createElement('div');
    block.id = id;
    block.className = 'ucrm-oidc-native-login';
    const link = document.createElement('a');
    link.href = href;
    link.textContent = metadata.loginLabel;
    link.className = 'ucrm-oidc-native-login-link';
    block.append(link);
    form.after(block);
    if (!document.getElementById('ucrm-oidc-native-style')) {
      const style = document.createElement('link');
      style.id = 'ucrm-oidc-native-style'; style.rel = 'stylesheet'; style.href = '/crm/_plugins/ucrm-oidc/public/login-button.css';
      document.head.append(style);
    }
  }
  const schedule = () => { if (!queued) { queued = true; requestAnimationFrame(refresh); } };
  const begin = () => {
    new MutationObserver(schedule).observe(document.body, {childList: true, subtree: true});
    addEventListener('popstate', schedule);
    addEventListener('hashchange', schedule);
    // Native SPA history changes need not emit popstate or replace the form.
    setInterval(schedule, 1000);
    schedule();
  };
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', begin, {once: true});
  else begin();
})();
