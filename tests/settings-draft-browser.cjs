'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {chromium} = require(process.env.OIDC229_PLAYWRIGHT_MODULE || 'playwright');
const origin = 'https://crm.example.test';
const entry = '/crm/_plugins/ucrm-oidc/public.php';
const owner = 'a'.repeat(64);
const key = 'ucrm-oidc-provider-draft:' + owner;
const fields = ['issuer', 'discoveryUrl', 'clientId', 'canonicalOrigin', 'scopes', 'loginLabel',
  'emailClaim', 'emailVerifiedClaim', 'clientAuthMethod', 'emailSource', 'maxAge', 'endpointOrigins'];
let passed = 0;
(async () => {
  const browser = await chromium.launch({channel: 'chrome', headless: true});
  try {
    const context = await browser.newContext();
    let state = 'editing', revision = '2', currentOwner = owner, csrf = 'old-csrf';
    const requests = [];
    await context.route('**/*', async route => {
      const url = new URL(route.request().url());
      if (url.origin !== origin) throw new Error('Unexpected external request');
      if (url.pathname.endsWith('/settings-draft.js')) return route.fulfill({contentType: 'text/javascript', body: fs.readFileSync(path.join(__dirname, '../plugin/public/settings-draft.js'), 'utf8')});
      if (url.pathname !== entry) throw new Error('Unexpected request');
      requests.push(route.request().method());
      const inputs = fields.map(name => `<input name="${name}" value="saved-${name}">`).join('');
      return route.fulfill({contentType: 'text/html', body: `<!doctype html><script defer src="/crm/_plugins/ucrm-oidc/public/settings-draft.js"></script><form method="post" data-oidc-provider-settings data-draft-owner="${currentOwner}" data-draft-state="${state}"><input name="csrf" value="${csrf}"><input name="expectedProviderRevision" value="${revision}">${inputs}<input type="password" name="clientSecret" value="NEVER_STORE_SECRET"><input name="unlisted" value="NEVER_STORE_OTHER"><button>Save</button></form><form><input type="password" name="otherSecret" value="NEVER_STORE_OTHER_SECRET"></form>`});
    });
    const page = await context.newPage();
    const errors = []; page.on('pageerror', e => errors.push(e.message));
    const load = () => page.goto(origin + entry, {waitUntil: 'networkidle'});
    const test = async (name, fn) => { await fn(); passed++; console.log('PASS ' + name); };
    await test('only explicit non-secret provider values are retained', async () => {
      await load(); await page.locator('[name=clientId]').fill('unsaved-client');
      await page.locator('form').first().evaluate(form => { form.addEventListener('submit', e => e.preventDefault()); form.dispatchEvent(new Event('submit', {cancelable: true})); });
      const raw = await page.evaluate(key => sessionStorage.getItem(key), key);
      assert(!raw.includes('NEVER_STORE') && !raw.includes('old-csrf'));
      const draft = JSON.parse(raw); assert.deepEqual(Object.keys(draft.values), fields);
      assert.equal(draft.values.clientId, 'unsaved-client');
      assert.equal(await page.evaluate(() => localStorage.length), 0);
    });
    await test('new native session reload restores draft without replacing its fresh CSRF', async () => {
      csrf = 'fresh-csrf'; await load();
      assert.equal(await page.locator('[name=clientId]').inputValue(), 'unsaved-client');
      assert.equal(await page.locator('[name=csrf]').inputValue(), 'fresh-csrf');
      assert.equal(requests.filter(x => x !== 'GET').length, 0);
      await page.getByText('Unsaved provider settings restored in this tab.', {exact: false}).waitFor();
    });
    await test('draft is scoped to the native administrator', async () => {
      currentOwner = 'b'.repeat(64); await load();
      assert.equal(await page.locator('[name=clientId]').inputValue(), 'saved-clientId'); currentOwner = owner;
    });
    await test('changed provider revision refuses stale draft', async () => {
      revision = '3'; await load();
      assert.equal(await page.locator('[name=clientId]').inputValue(), 'saved-clientId');
      assert.equal(await page.evaluate(key => sessionStorage.getItem(key), key), null); revision = '2';
    });
    await test('recovery response stores rendered inputs without storing secrets', async () => {
      state = 'recovery'; await load();
      const raw = await page.evaluate(key => sessionStorage.getItem(key), key);
      assert.equal(JSON.parse(raw).values.clientId, 'saved-clientId'); assert(!raw.includes('NEVER_STORE'));
    });
    await test('successful save removes draft', async () => {
      state = 'saved'; await load(); assert.equal(await page.evaluate(key => sessionStorage.getItem(key), key), null); state = 'editing';
    });
    const write = draft => page.evaluate(({key, draft}) => sessionStorage.setItem(key, JSON.stringify(draft)), {key, draft});
    const values = Object.fromEntries(fields.map(name => [name, 'draft-' + name]));
    await test('expired and future dated drafts are discarded', async () => {
      for (const at of [Date.now() - 16 * 60000, Date.now() + 60000]) {
        await write({at, revision, values}); await load();
        assert.equal(await page.locator('[name=clientId]').inputValue(), 'saved-clientId');
        assert.equal(await page.evaluate(key => sessionStorage.getItem(key), key), null);
      }
    });
    await test('tampered and oversized drafts cannot restore arbitrary fields', async () => {
      for (const draftValues of [{...values, clientSecret: 'bad'}, {...values, clientId: 'x'.repeat(2049)}, {...values, issuer: {html: '<script>'}}]) {
        await write({at: Date.now(), revision, values: draftValues}); await load();
        assert.equal(await page.locator('[name=clientId]').inputValue(), 'saved-clientId');
        assert.equal(await page.evaluate(key => sessionStorage.getItem(key), key), null);
      }
    });
    await test('restore treats markup as field text and supports explicit discard', async () => {
      await write({at: Date.now(), revision, values: {...values, clientId: '<img src=x onerror="bad()">'}}); await load();
      assert.equal(await page.locator('img').count(), 0);
      assert.equal(await page.locator('[name=clientId]').inputValue(), '<img src=x onerror="bad()">');
      await page.getByRole('button', {name: 'Discard restored draft'}).click();
      assert.equal(await page.locator('[name=clientId]').inputValue(), 'saved-clientId');
      assert.equal(await page.evaluate(key => sessionStorage.getItem(key), key), null);
    });
    await test('storage restrictions leave the provider form usable', async () => {
      await context.addInitScript(() => { Object.defineProperty(window, 'sessionStorage', {get() {throw new Error('blocked');}}); });
      await load(); await page.locator('[name=clientId]').fill('still-editable');
      await page.locator('form').first().evaluate(form => { form.addEventListener('submit', e => e.preventDefault()); form.dispatchEvent(new Event('submit', {cancelable: true})); });
      assert.equal(await page.locator('[name=clientId]').inputValue(), 'still-editable');
    });
    assert.deepEqual(errors, []);
    console.log(JSON.stringify({suite: 'settings-draft-browser', passed, failed: 0}));
  } finally {await browser.close();}
})().catch(e => {console.error(e); process.exitCode = 1;});
