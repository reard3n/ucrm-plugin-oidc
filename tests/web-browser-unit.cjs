'use strict';
// Browser behavior only; every HTTP request is intercepted with synthetic data.
// This does not replace native/provider release acceptance and never logs artifacts.
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const assert = require('node:assert/strict');
const playwright = require(process.env.OIDC229_PLAYWRIGHT_MODULE || 'playwright');
const assets = path.resolve(__dirname, '../plugin/public');
const origin = 'https://crm.example.test';
const entry = '/crm/_plugins/ucrm-oidc/public.php';
const token = '33333333-3333-4333-8333-333333333333';
const tests = [];
let activeTest = 'launch';
async function test(name, work) { activeTest = name; await work(); tests.push({name, passed: true}); }
const nativeForm = '<form id="native-password"><label>Username<input id="username" name="username"></label><label>Password<input name="password" type="password"></label><button type="submit">Sign in</button></form>';
const completion = '<!doctype html><html><head><script defer src="/crm/_plugins/ucrm-oidc/public/web.js"></script></head><body><div id="oidc-signin">'
  + '<form id="oidc-handoff" method="post" action="' + entry + '?action=handoff"><input name="csrf" type="hidden" value="synthetic-csrf"><input name="flow" type="hidden" value="' + 'f'.repeat(64) + '"><button>Continue signing in</button></form>'
  + '<form id="oidc-mfa" method="post" action="' + entry + '?action=mfa-complete" hidden><input name="csrf" type="hidden" value="synthetic-csrf"><input name="flow" type="hidden" value="' + 'f'.repeat(64) + '"><label>Code<input name="otp" required pattern="[0-9]{6}" maxlength="6"></label><button>Verify</button></form><p id="oidc-progress" role="status"></p></div></body></html>';

(async () => {
  const browser = await playwright.chromium.launch({channel: 'chrome', headless: true});
  let context;
  try {
    context = await browser.newContext();
    let metadata = {enabled: true, ready: true, loginLabel: 'SSO <img src=x onerror=bad>'};
    let statusRequests = 0;
    let statusFailure = false;
    let flowReply = {ok: true, kind: 'session', returnPath: '/crm/'};
    let flowStatus = 200;
    let nativeStatus = 200;
    let abortFlow = false;
    let submitted = [];
    let checkedTokens = [];
    const unexpected = [];
    await context.route('**/*', async route => {
      const request = route.request();
      const url = new URL(request.url());
      if (url.origin !== origin) { unexpected.push('external-request'); return route.abort(); }
      if (url.pathname.endsWith('/public/web.js') || url.pathname.endsWith('/public/login-button.js')) return route.fulfill({contentType: 'text/javascript', body: fs.readFileSync(path.join(assets, path.basename(url.pathname)), 'utf8')});
      if (url.pathname.endsWith('/public/login-button.css')) return route.fulfill({contentType: 'text/css', body: ''});
      if (url.pathname === '/nms/login') return route.fulfill({contentType: 'text/html', body: '<!doctype html><html><head><script defer src="/crm/_plugins/ucrm-oidc/public/login-button.js"></script></head><body><div id="app"></div></body></html>'});
      if (url.pathname === entry && url.searchParams.get('action') === 'status') {
        statusRequests++;
        return route.fulfill({status: statusFailure ? 503 : 200, contentType: 'application/json', body: JSON.stringify(metadata)});
      }
      if (url.pathname === entry && url.searchParams.get('action') === 'complete') return route.fulfill({contentType: 'text/html', body: completion});
      if (url.pathname === entry && ['handoff', 'mfa-complete'].includes(url.searchParams.get('action'))) {
        submitted.push({action: url.searchParams.get('action'), values: new URLSearchParams(request.postData()), method: request.method()});
        if (abortFlow) return route.abort();
        return route.fulfill({status: flowStatus, contentType: 'application/json', headers: flowReply.kind === 'session' ? {'x-auth-token': token} : {}, body: JSON.stringify(flowReply)});
      }
      if (url.pathname === '/nms/api/v2.1/user/check-session') {
        checkedTokens.push(request.headers()['x-auth-token']);
        assert.equal(request.method(), 'POST');
        return route.fulfill({status: nativeStatus, contentType: 'application/json', body: '{}'});
      }
      if (url.pathname === '/crm/') return route.fulfill({contentType: 'text/html', body: '<!doctype html><h1>Native CRM fixture</h1>'});
      unexpected.push('unexpected-path');
      return route.abort();
    });
    let page = await context.newPage();
    const errors = [];
    page.on('pageerror', () => errors.push('browser-error'));
    await test('login button waits for actual native SPA form', async () => {
      await page.goto(origin + '/nms/login');
      assert.equal(await page.locator('#ucrm-oidc-native-login').count(), 0);
      await page.locator('#app').evaluate((node, html) => { node.innerHTML = html; }, nativeForm);
      await page.locator('#ucrm-oidc-native-login a').waitFor();
      assert.equal(await page.locator('#native-password').evaluate(node => node.outerHTML), nativeForm);
      assert.equal(await page.locator('#ucrm-oidc-native-login a').textContent(), metadata.loginLabel);
      assert.equal(await page.locator('#ucrm-oidc-native-login img').count(), 0);
      assert.equal(await page.locator('#ucrm-oidc-native-login a').getAttribute('href'), entry + '?action=start&return=%2Fnms%2F');
    });
    await test('repeated DOM mutations never duplicate button or refetch continuously', async () => {
      const before = statusRequests;
      await page.evaluate(() => { for (let i = 0; i < 10; i++) document.body.append(document.createElement('span')); });
      await page.waitForTimeout(200);
      assert.equal(await page.locator('#ucrm-oidc-native-login').count(), 1);
      assert.equal(statusRequests, before);
    });
    await test('native CRM deep-link survives the OIDC login affordance', async () => {
      const destination = '/crm/client/123?tab=services';
      await page.evaluate(value => { history.replaceState({}, '', '/nms/login?returnurl=' + encodeURIComponent(value)); document.body.append(document.createElement('span')); }, destination);
      const expected = entry + '?action=start&return=' + encodeURIComponent(destination);
      await page.waitForFunction(expected => document.querySelector('#ucrm-oidc-native-login a')?.getAttribute('href') === expected, expected);
      assert.equal(await page.locator('#native-password').evaluate(node => node.outerHTML), nativeForm);
    });
    await test('duplicate and unsafe native returnurl fall back safely', async () => {
      const values = ['https://attacker.example.test/', '//attacker.example.test/', '/crm/../logout', '/crm/%2f%2fattacker', '/nms/api/v2.1/user', '/crm/%6cogin', '/crm/%ZZ', '/crm/client#fragment'];
      const queries = values.map(value => '?returnurl=' + encodeURIComponent(value));
      queries.push('?returnurl=%2Fcrm%2Fclient&returnurl=%2Fnms%2Fsites');
      for (const query of queries) {
        await page.evaluate(query => { history.replaceState({}, '', '/nms/login' + query); document.body.append(document.createElement('span')); }, query);
        await page.waitForFunction(expected => document.querySelector('#ucrm-oidc-native-login a')?.getAttribute('href') === expected, entry + '?action=start&return=%2Fnms%2F');
      }
    });
    await test('SPA navigation removes login-only affordance', async () => {
      await page.evaluate(() => { history.pushState({}, '', '/nms/sites'); document.body.append(document.createElement('span')); });
      await page.locator('#ucrm-oidc-native-login').waitFor({state: 'detached'});
      await page.evaluate(() => { history.pushState({}, '', '/nms/login'); document.body.append(document.createElement('span')); });
      await page.locator('#ucrm-oidc-native-login a').waitFor();
    });
    await test('native disable removes affordance while preserving password form', async () => {
      metadata.enabled = false;
      await page.evaluate(() => { const nativeNow = Date.now; Date.now = () => nativeNow() + 16000; document.body.append(document.createElement('span')); });
      await page.locator('#ucrm-oidc-native-login').waitFor({state: 'detached'});
      assert.equal(await page.locator('#native-password').evaluate(node => node.outerHTML), nativeForm);
    });
    await test('missing adapter metadata leaves native login intact', async () => {
      statusFailure = true;
      await page.reload();
      await page.locator('#app').evaluate((node, html) => { node.innerHTML = html; }, nativeForm);
      await page.waitForTimeout(200);
      assert.equal(await page.locator('#ucrm-oidc-native-login').count(), 0);
      assert.equal(await page.locator('#native-password').evaluate(node => node.outerHTML), nativeForm);
    });
    await test('native handoff checks session then persists exact native token and navigates', async () => {
      await page.goto(origin + entry + '?action=complete&flow=' + 'f'.repeat(64));
      await page.locator('#oidc-handoff button').click();
      await page.waitForURL(origin + '/crm/');
      assert.equal(await page.evaluate(() => localStorage.getItem('x-auth-token')), token);
      assert.deepEqual(checkedTokens, [token]);
      assert.deepEqual([...submitted[0].values.keys()].sort(), ['csrf', 'flow']);
      assert.equal(submitted[0].method, 'POST');
      assert(!submitted[0].values.toString().includes(token));
    });
    await test('failed native check never replaces existing localStorage or navigates', async () => {
      nativeStatus = 401;
      await page.goto(origin + entry + '?action=complete&flow=' + 'f'.repeat(64));
      await page.evaluate(() => localStorage.setItem('x-auth-token', 'previous-native-token'));
      await page.locator('#oidc-handoff button').click();
      await page.getByRole('status').filter({hasText: 'Sign-in could not be completed.'}).waitFor();
      assert.equal(await page.evaluate(() => localStorage.getItem('x-auth-token')), 'previous-native-token');
      assert.equal(await page.locator('#oidc-handoff button').isDisabled(), true);
      assert.equal(new URL(page.url()).searchParams.get('action'), 'complete');
    });
    await test('MFA challenge stays server-side and invalid OTP permits explicit retry', async () => {
      nativeStatus = 200; flowReply = {ok: true, kind: 'mfa'};
      await page.goto(origin + entry + '?action=complete&flow=' + 'f'.repeat(64));
      await page.locator('#oidc-handoff button').click();
      await page.locator('#oidc-mfa').waitFor({state: 'visible'});
      assert.equal(await page.locator('#oidc-handoff').isHidden(), true);
      flowReply = {ok: false, error: {code: 'MFA_INVALID'}}; flowStatus = 400;
      await page.locator('[name=otp]').fill('123456');
      await page.locator('#oidc-mfa button').click();
      await page.getByRole('status').filter({hasText: 'authenticator code was not accepted'}).waitFor();
      assert.equal(await page.locator('[name=otp]').inputValue(), '');
      assert.equal(await page.locator('#oidc-mfa button').isDisabled(), false);
      assert.equal(submitted.at(-1).action, 'mfa-complete');
      assert.equal(submitted.at(-1).values.get('otp'), '123456');
      assert.deepEqual([...submitted.at(-1).values.keys()].sort(), ['csrf', 'flow', 'otp']);
      flowReply = {ok: true, kind: 'session', returnPath: '/crm/'}; flowStatus = 200;
      await page.locator('[name=otp]').fill('654321');
      await page.locator('#oidc-mfa button').click();
      await page.waitForURL(origin + '/crm/');
    });
    await test('uncertain issuance never enables a browser retry', async () => {
      abortFlow = true;
      await page.goto(origin + entry + '?action=complete&flow=' + 'f'.repeat(64));
      await page.locator('#oidc-handoff button').click();
      await page.getByRole('status').filter({hasText: 'Sign-in could not be completed.'}).waitFor();
      assert.equal(await page.locator('#oidc-handoff button').isDisabled(), true);
    });
    await test('malformed return never navigates externally', async () => {
      abortFlow = false; flowReply = {ok: true, kind: 'session', returnPath: '//attacker.example.test/'};
      await page.goto(origin + entry + '?action=complete&flow=' + 'f'.repeat(64));
      const before = checkedTokens.length;
      await page.locator('#oidc-handoff button').click();
      await page.getByRole('status').filter({hasText: 'Sign-in could not be completed.'}).waitFor();
      assert.equal(checkedTokens.length, before);
      assert.equal(new URL(page.url()).origin, origin);
    });
    await test('no browser script errors or unexpected network destinations', async () => {
      assert.deepEqual(errors, []); assert.deepEqual(unexpected, []);
    });
    await test('form Origin, provider privacy, clean callback redirect and fetch handoff use coherent policies', async () => {
      const cspContext = await browser.newContext();
      try {
        let formOrigin;
        let providerReferrer;
        let completionReferrer;
        let handoffOrigin;
        await cspContext.route('**/*', route => {
          const req = route.request();
          const url = new URL(req.url());
          const policy = "default-src 'none'; base-uri 'none'; form-action 'self'";
          if (url.origin === origin && url.pathname === '/start' && req.method() === 'GET') return route.fulfill({contentType: 'text/html', headers: {'Content-Security-Policy': policy + ' https://idp.example.test;', 'Referrer-Policy': 'same-origin'}, body: '<!doctype html><form method="post" action="/start"><button>Start</button></form>'});
          if (url.origin === origin && url.pathname === '/start' && req.method() === 'POST') {
            formOrigin = req.headers().origin;
            return route.fulfill({status: 303, headers: {'Location': 'https://idp.example.test/authorize', 'Content-Security-Policy': policy + ';', 'Referrer-Policy': 'no-referrer'}, body: ''});
          }
          if (url.origin === 'https://idp.example.test') {
            providerReferrer = req.headers().referer;
            return route.fulfill({contentType: 'text/html', body: '<!doctype html><a href="' + origin + entry + '?action=callback&amp;code=synthetic-code&amp;state=synthetic-state">Return</a>'});
          }
          if (url.origin === origin && url.pathname === entry && url.searchParams.get('action') === 'callback') return route.fulfill({status: 303, headers: {Location: entry + '?action=complete&flow=' + 'f'.repeat(64), 'Referrer-Policy': 'no-referrer'}, body: ''});
          if (url.origin === origin && url.pathname === entry && url.searchParams.get('action') === 'complete') {
            completionReferrer = req.headers().referer;
            return route.fulfill({contentType: 'text/html', headers: {'Referrer-Policy': 'no-referrer'}, body: completion});
          }
          if (url.origin === origin && url.pathname.endsWith('/public/web.js')) return route.fulfill({contentType: 'text/javascript', body: fs.readFileSync(path.join(assets, 'web.js'), 'utf8')});
          if (url.origin === origin && url.pathname === entry && url.searchParams.get('action') === 'handoff') {
            handoffOrigin = req.headers().origin;
            return route.fulfill({contentType: 'application/json', headers: {'Referrer-Policy': 'no-referrer'}, body: '{"ok":true,"kind":"mfa"}'});
          }
          return route.abort();
        });
        const cspPage = await cspContext.newPage();
        await cspPage.goto(origin + '/start');
        await cspPage.getByRole('button', {name: 'Start'}).click();
        await cspPage.waitForURL('https://idp.example.test/authorize');
        assert.equal(formOrigin, origin);
        assert.equal(providerReferrer, undefined);
        await cspPage.getByRole('link', {name: 'Return'}).click();
        await cspPage.waitForURL(url => url.origin === origin && url.searchParams.get('action') === 'complete');
        assert.equal(completionReferrer, undefined);
        assert.equal(new URL(cspPage.url()).searchParams.has('code'), false);
        assert.equal(new URL(cspPage.url()).searchParams.has('state'), false);
        await cspPage.locator('#oidc-handoff button').click();
        await cspPage.locator('#oidc-mfa').waitFor({state: 'visible'});
        assert.equal(handoffOrigin, origin);
      } finally { await cspContext.close(); }
    });
    console.log(JSON.stringify({suite: 'web-browser-unit', passed: tests.length, failed: 0, tests}));
  } catch (_) {
    console.log(JSON.stringify({suite: 'web-browser-unit', passed: tests.length, failed: 1, tests: [...tests, {name: activeTest, passed: false}]}));
    process.exitCode = 1;
  } finally {
    if (context) await context.close();
    await browser.close();
  }
})().catch(() => { console.log(JSON.stringify({suite: 'web-browser-unit', failed: 1, test: 'browser-launch'})); process.exitCode = 1; });
