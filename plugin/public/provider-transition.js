'use strict';
(() => {
  const link = document.getElementById('oidc-provider-continue');
  const progress = document.getElementById('oidc-provider-progress');
  const recovery = document.getElementById('oidc-provider-recovery');
  if (!link || !progress || !recovery) return;
  const failure = () => {
    progress.textContent = 'Provider sign-in has not opened. Choose Continue to provider, start again, or use native password login. If navigation is still blocked, contact your administrator.';
    progress.dataset.failed = '1';
    recovery.hidden = false;
  };
  const destination = () => {
    const url = new URL(link.getAttribute('href'));
    if (url.protocol !== 'https:' || url.username || url.password || url.hash
      || url.origin !== link.dataset.providerOrigin || url.href.length > 8192) throw new Error('Invalid destination');
    return url;
  };
  link.addEventListener('click', event => {
    try { destination(); } catch (_) { event.preventDefault(); failure(); }
  });
  try {
    const url = destination();
    if (performance.getEntriesByType('navigation')[0]?.type === 'back_forward') { failure(); return; }
    // Reveal recovery only if the browser blocks or stalls navigation.
    // No automatic retry or new authorization transaction is submitted.
    window.setTimeout(failure, 10000);
    window.addEventListener('pageshow', event => { if (event.persisted) failure(); });
    window.location.replace(url.href);
  } catch (_) { failure(); }
})();
