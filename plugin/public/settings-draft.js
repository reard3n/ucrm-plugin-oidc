'use strict';
(() => {
  const form = document.querySelector('form[data-oidc-provider-settings]');
  if (!form || !/^[0-9a-f]{64}$/.test(form.dataset.draftOwner || '')) return;
  // Only provider configuration belongs in a draft. Never serialize a whole
  // form/page: credentials, CSRF, native tokens and account-link inputs are excluded.
  const fields = ['issuer', 'discoveryUrl', 'clientId', 'canonicalOrigin', 'scopes',
    'loginLabel', 'emailClaim', 'emailVerifiedClaim', 'clientAuthMethod', 'emailSource',
    'maxAge', 'endpointOrigins'];
  const key = 'ucrm-oidc-provider-draft:' + form.dataset.draftOwner;
  const revision = form.elements.namedItem('expectedProviderRevision')?.value;
  const ttl = 15 * 60 * 1000;
  const clear = () => { try { sessionStorage.removeItem(key); } catch (_) {} };
  const notice = text => {
    const message = document.createElement('p');
    message.className = 'oidc-notice';
    message.setAttribute('role', 'status');
    message.textContent = text;
    form.before(message);
    return message;
  };
  const save = () => {
    const values = {};
    for (const name of fields) {
      const value = form.elements.namedItem(name)?.value;
      if (typeof value !== 'string' || value.length > (name === 'endpointOrigins' ? 8192 : 2048)) return;
      values[name] = value;
    }
    try { sessionStorage.setItem(key, JSON.stringify({at: Date.now(), revision, values})); }
    catch (_) { /* The server still returns non-secret inputs on recent-auth refusal. */ }
  };
  if (form.dataset.draftState === 'saved') {
    clear();
  } else if (form.dataset.draftState === 'recovery') {
    save();
  } else {
    try {
      const raw = sessionStorage.getItem(key);
      if (raw) {
        if (raw.length > 32768) throw new Error('Invalid draft');
        const draft = JSON.parse(raw);
        if (!Number.isFinite(draft.at) || draft.at > Date.now() || draft.at < Date.now() - ttl
          || !draft.values || typeof draft.values !== 'object' || Array.isArray(draft.values)
          || Object.keys(draft.values).length !== fields.length
          || fields.some(name => typeof draft.values[name] !== 'string'
            || draft.values[name].length > (name === 'endpointOrigins' ? 8192 : 2048))) throw new Error('Invalid draft');
        if (draft.revision !== revision) {
          clear();
          notice('Saved provider settings changed. The older draft was not restored; review the current values before editing.');
        } else {
          for (const name of fields) form.elements.namedItem(name).value = draft.values[name];
          const message = notice('Unsaved provider settings restored in this tab. Review before saving. Client secrets must be entered again.');
          const discard = document.createElement('button');
          discard.type = 'button';
          discard.className = 'button';
          discard.textContent = 'Discard restored draft';
          discard.addEventListener('click', () => { clear(); form.reset(); message.remove(); });
          message.append(' ', discard);
        }
      }
    } catch (_) { clear(); }
  }
  form.addEventListener('submit', save);
})();
