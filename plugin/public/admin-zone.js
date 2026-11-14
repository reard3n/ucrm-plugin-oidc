(() => {
  'use strict';
  const entry = '/crm/_plugins/ucrm-oidc/public.php?action=admin';
  const sectionId = 'ucrm-oidc-provider-settings';

  async function mount() {
    const currentPath = location.pathname;
    if (!/^\/crm\/system\/plugins\/[1-9][0-9]*\/configuration$/.test(currentPath)) return;
    const container = document.getElementById('configuration_form');
    const form = document.getElementById('plugin-configuration-form');
    if (!container || !form || !container.contains(form)
      || !form.querySelector('input[name="plugin_configuration[configuration][oidcEnabled]"]')
      || document.getElementById(sectionId)) return;
    const formUrl = new URL(form.getAttribute('action') || location.href, location.href);
    if (formUrl.origin !== location.origin || formUrl.pathname !== currentPath) return;

    // The native checkbox is only a hint. The protected page supplies its own
    // native plugin ID from ucrm.json, so another plugin cannot be mistaken for
    // this one merely because it uses the same configuration-field name.
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 5000);
    try {
      const response = await fetch(entry, {credentials: 'same-origin', cache: 'no-store',
        redirect: 'error', signal: controller.signal, headers: {Accept: 'text/html'}});
      if (!response.ok || !(response.headers.get('content-type') || '').startsWith('text/html')) return;
      const markup = await response.text();
      if (markup.length > 262144) return;
      const page = new DOMParser().parseFromString(markup, 'text/html');
      const links = [...page.querySelectorAll('a[href]')].filter(link => {
        const target = new URL(link.getAttribute('href'), location.origin);
        return target.origin === location.origin && target.pathname === currentPath
          && target.search === '' && target.hash === '';
      });
      if (links.length !== 1 || location.pathname !== currentPath || !container.isConnected
        || document.getElementById(sectionId)) return;

      const section = document.createElement('section');
      section.id = sectionId;
      const title = document.createElement('h2');
      title.textContent = 'OpenID Connect provider settings';
      const help = document.createElement('p');
      help.textContent = 'Save provider settings and the client secret below. The native enable and execution settings above are saved separately.';
      const link = document.createElement('a');
      link.href = entry;
      link.textContent = 'Open provider settings in a separate page';
      link.target = '_blank';
      link.rel = 'noopener noreferrer';
      const frame = document.createElement('iframe');
      frame.title = 'OpenID Connect provider settings';
      frame.referrerPolicy = 'no-referrer';
      frame.style.cssText = 'display:block;width:100%;height:1000px;border:0;margin-top:16px;';
      let observer;
      frame.addEventListener('load', () => {
        if (observer) observer.disconnect();
        try {
          const body = frame.contentDocument.body;
          const content = body.querySelector('main.oidc-container');
          const resize = () => {
            if (!frame.isConnected || !body) return;
            // Native CRM CSS gives html/body height:100%, so their rectangles
            // report the current iframe viewport rather than overflowing forms.
            // Measure the intrinsic content root to also shrink after reflow;
            // observing the percentage-height body would create feedback.
            const height = content ? content.offsetTop + content.scrollHeight
              : Math.max(body.scrollHeight, frame.contentDocument.documentElement.scrollHeight);
            frame.style.height = Math.min(6000, Math.max(320, Math.ceil(height))) + 'px';
          };
          resize();
          if (typeof ResizeObserver === 'function') {
            observer = new ResizeObserver(resize);
            observer.observe(content || body);
          }
        } catch (_) { /* A provider navigation keeps the fixed, usable frame size. */ }
      });
      frame.src = entry;
      section.append(title, help, link, frame);
      container.insertAdjacentElement('afterend', section);
    } catch (_) { /* Native configuration remains usable if the plugin is unavailable. */ }
    finally { clearTimeout(timeout); }
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', mount, {once: true});
  else void mount();
})();
