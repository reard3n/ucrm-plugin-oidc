'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const https = require('node:https');
const {chromium} = require(process.env.OIDC229_PLAYWRIGHT_MODULE || 'playwright');
const original = JSON.parse(fs.readFileSync(process.env.OIDC_START_FIXTURE, 'utf8'));
const baseline = process.argv.includes('--expect-blocked');
const entry = '/crm/_plugins/ucrm-oidc/public.php';
let passed = 0;
(async () => {
  let fixture, crm, issuer, upstream, active;
  const server = https.createServer(original.tls, async (req, res) => {
    const send = (status, headers = {}, body = '') => { res.writeHead(status, {'Cache-Control': 'no-store', ...headers}); res.end(body); };
    try {
      const url = new URL(req.url, 'https://' + req.headers.host);
      if (url.pathname === '/favicon.ico') return send(204);
      if (url.origin === crm) {
        if (url.pathname.startsWith('/crm/_plugins/ucrm-oidc/public/')) {
          const name = path.basename(url.pathname);
          if (name.endsWith('.js')) return send(200, {'Content-Type': 'text/javascript'}, fs.readFileSync(path.join(__dirname, '../plugin/public', name)));
          return send(200, {'Content-Type': 'text/css'});
        }
        if (url.pathname === '/crm/dist/main.min.css' || url.pathname === '/nms/fonts.min.css') return send(200, {'Content-Type': 'text/css'});
        if (url.pathname === entry && url.searchParams.get('action') === 'start') {
          const response = fixture[active.mode][req.method === 'POST' ? 'post' : 'get'];
          if (req.method === 'POST') {
            const chunks = []; for await (const chunk of req) chunks.push(chunk);
            const body = new URLSearchParams(Buffer.concat(chunks).toString());
            active.starts++; assert.equal(body.get('csrf'), fixture.csrf);
            assert.equal(body.get('preview'), active.mode === 'preview' ? '1' : '0');
            assert.equal(req.headers.origin, crm);
          }
          return send(response.status, response.headers, response.body);
        }
        if (url.pathname === entry && url.searchParams.get('action') === 'callback') {
          active.callbacks++; assert.equal(url.searchParams.get('state'), fixture.parameters.state);
          assert.equal(url.searchParams.get('code'), 'synthetic-code');
          return send(303, {Location: entry + '?action=complete&flow=' + 'f'.repeat(64), 'Referrer-Policy': 'no-referrer'});
        }
        if (url.pathname === entry && url.searchParams.get('action') === 'complete') {
          const response = fixture[active.mode].complete;
          return send(response.status, response.headers, response.body);
        }
        if (url.pathname === entry && url.searchParams.get('action') === 'handoff') {
          assert.equal(req.method, 'POST'); assert.equal(req.headers.origin, crm);
          const chunks = []; for await (const chunk of req) chunks.push(chunk);
          const body = new URLSearchParams(Buffer.concat(chunks).toString());
          assert.equal(body.get('csrf'), fixture.flowCsrf);
          assert.equal(body.get('flow'), 'f'.repeat(64)); active.handoffs = (active.handoffs || 0) + 1;
          const response = fixture.normal.handoff;
          return send(response.status, response.headers, response.body);
        }
        if (url.pathname === '/nms/api/v2.1/user/check-session') {
          assert.equal(req.method, 'POST'); assert.equal(req.headers['x-auth-token'], fixture.normal.handoff.headers['x-auth-token']);
          return send(200, {'Content-Type': 'application/json'}, '{}');
        }
        if (url.pathname === '/crm/') return send(200, {'Content-Type': 'text/html'}, '<h1>Native CRM fixture</h1>');
        if (url.pathname === entry && url.searchParams.get('action') === 'error') return send(fixture.expired.status, fixture.expired.headers, fixture.expired.body);
      }
      if (url.origin === issuer) {
        if (url.pathname === '/authorize') {
          active.providerRequests.push(req.headers); assert.equal(req.method, 'GET');
          for (const [name, value] of Object.entries(fixture.parameters)) assert.equal(url.searchParams.get(name), value);
          if (active.stall) { active.resume = () => send(303, {Location: issuer + '/oidc/interaction/example'}); return; }
          return send(303, {Location: issuer + '/oidc/interaction/example'});
        }
        const next = {'/oidc/interaction/example': '/auth/oidc/interaction/example', '/auth/oidc/interaction/example': '/oauth/connect/upstream', '/oauth/connect/upstream': upstream + '/login'}[url.pathname];
        if (next) return send(302, {Location: next.startsWith('https:') ? next : issuer + next});
        if (url.pathname === '/resume') return send(303, {Location: crm + entry + '?action=callback&code=synthetic-code&state=' + fixture.parameters.state, 'Referrer-Policy': 'no-referrer'});
      }
      if (url.origin === upstream && url.pathname === '/login') return send(200, {'Content-Type': 'text/html', 'Referrer-Policy': 'no-referrer'}, `<h1>Federated sign-in</h1><form action="${issuer}/resume" method="get"><button>Finish provider login</button></form>`);
      throw new Error('Unexpected path: ' + url.origin + url.pathname);
    } catch (error) { active?.errors.push(error.message); send(500); }
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  [crm, issuer, upstream] = ['crm', 'idp', 'login'].map(host => `https://${host}.example.test:${port}`);
  fixture = JSON.parse(JSON.stringify(original).replaceAll('https://crm.example.test', crm).replaceAll('https://idp.example.test', issuer)
    .replaceAll(encodeURIComponent('https://crm.example.test'), encodeURIComponent(crm)));
  // Use a real loopback HTTPS server: request interception can skip later
  // redirects and therefore cannot establish Chromium's form-action behavior.
  const browser = await chromium.launch({channel: 'chrome', headless: true, args: ['--no-proxy-server', '--host-resolver-rules=MAP *.example.test 127.0.0.1']});
  try {
    for (const mode of ['normal', 'preview']) {
      for (const scripting of baseline ? [true] : [true, false]) {
        active = {mode, starts: 0, callbacks: 0, providerRequests: [], errors: []};
        // Generated certificate belongs only to this loopback fixture.
        const context = await browser.newContext({javaScriptEnabled: scripting, ignoreHTTPSErrors: true});
        const page = await context.newPage(), cspErrors = [];
        page.on('pageerror', e => active.errors.push(e.message));
        page.on('console', m => { if (m.type() === 'error' && /form-action|Content Security Policy/i.test(m.text())) cspErrors.push(m.text()); });
        await page.goto(crm + entry + '?action=start&preview=' + (mode === 'preview' ? '1' : '0'));
        if (baseline) await page.locator('form button[type=submit]').click();
        if (baseline) {
          await page.waitForTimeout(1200);
          assert(cspErrors.length > 0, 'Old POST redirect must reproduce the CSP failure: ' + JSON.stringify({url:page.url(), errors:active.errors, providerRequests:active.providerRequests.length, body:(await page.locator('body').innerText()).slice(0,300)}));
          assert.equal(new URL(page.url()).origin, crm); assert.equal(active.callbacks, 0);
        } else {
          if (!scripting) {
            await page.getByRole('alert').filter({hasText: 'JavaScript is disabled'}).waitFor();
            assert.equal(new URL(page.url()).origin, crm);
            assert.equal(await page.getByRole('link', {name: 'Native password login', exact: true}).count(), 1);
            assert.equal(await page.getByRole('link', {name: 'Plugin settings', exact: true}).count(), 0);
            assert.equal(await page.getByRole('button').count(), 0);
            assert.equal(active.starts, 0); assert.equal(active.providerRequests.length, 0);
            passed++; console.log('PASS ' + mode + ' disabled JavaScript offers failure-only password recovery');
            await context.close(); continue;
          }
          await page.getByRole('heading', {name: 'Federated sign-in'}).waitFor();
          assert.equal(new URL(page.url()).origin, upstream);
          await page.getByRole('button', {name: 'Finish provider login'}).click();
          await page.getByRole('heading', {name: mode === 'normal' ? 'Native CRM fixture' : 'Provider identity preview'}).waitFor();
          assert.equal(active.handoffs || 0, mode === 'normal' ? 1 : 0);
          if (mode === 'normal') assert.equal(await page.evaluate(() => localStorage.getItem('x-auth-token')), fixture.normal.handoff.headers['x-auth-token']);
          assert.equal(active.callbacks, 1); assert.equal(active.providerRequests.length, 1);
          assert(!active.providerRequests[0].referer, 'Transition must not send a referrer to the issuer');
          assert.deepEqual(cspErrors, []);
        }
        assert.equal(active.starts, 1); assert.deepEqual(active.errors, []);
        console.log('PASS ' + mode + (baseline ? ' reproduces old CSP blocker' : scripting ? ' automatic federated navigation' : ' manual navigation without JavaScript'));
        passed++; await context.close();
      }
    }
    if (!baseline) {
      active = {mode: 'normal', stall: true, starts: 0, callbacks: 0, providerRequests: [], errors: []};
      const context = await browser.newContext({ignoreHTTPSErrors: true});
      const page = await context.newPage();
      await page.goto(crm + entry + '?action=start', {waitUntil: 'commit'});
      const deadline = Date.now() + 5000;
      while (!active.providerRequests.length && Date.now() < deadline) await new Promise(resolve => setTimeout(resolve, 20));
      assert.equal(active.providerRequests.length, 1);
      // Model the browser's Stop action while the provider has not responded.
      // Provisional navigation suspends DOM evaluation until it is cancelled.
      const cdp = await context.newCDPSession(page); await cdp.send('Page.stopLoading');
      await page.waitForFunction(() => document.getElementById('oidc-provider-progress')?.textContent.includes('Provider sign-in has not opened.'), null, {timeout: 15000});
      assert.equal(active.starts, 1); assert.equal(active.providerRequests.length, 1);
      assert(await page.getByRole('link', {name: 'Start sign-in again', exact: true}).isVisible());
      assert(await page.getByRole('link', {name: 'Native password login', exact: true}).isVisible());
      assert.equal(await page.getByRole('link', {name: 'Plugin settings', exact: true}).count(), 0);
      active.stall = false;
      await page.getByRole('link', {name: 'Continue to provider', exact: true}).click();
      await page.getByRole('heading', {name: 'Federated sign-in'}).waitFor();
      assert.deepEqual(active.errors, []);
      assert.equal(active.starts, 1); assert.equal(active.providerRequests.length, 2);
      console.log('PASS interrupted provider navigation offers recovery and explicit retry only');
      passed++; await context.close();
      active = {mode: 'normal', starts: 0, callbacks: 0, providerRequests: [], errors: []};
      const expiredContext = await browser.newContext({ignoreHTTPSErrors: true});
      const expiredPage = await expiredContext.newPage();
      await expiredPage.goto(crm + entry + '?action=error&reason=FLOW_USED');
      await expiredPage.getByRole('alert').filter({hasText: 'expired or has already been used'}).waitFor();
      assert(await expiredPage.getByRole('link', {name: 'Start sign-in again', exact: true}).isVisible());
      assert(await expiredPage.getByRole('link', {name: 'Native password login', exact: true}).isVisible());
      assert.equal(await expiredPage.getByRole('link', {name: 'Plugin settings', exact: true}).count(), 0);
      assert.equal(active.starts, 0); assert.deepEqual(active.errors, []);
      console.log('PASS expired or consumed flow requires explicit fresh login and exposes no settings link');
      passed++; await expiredContext.close();
    }
    console.log(JSON.stringify({suite: 'start-transition-browser', baseline, passed, failed: 0}));
  } finally {await browser.close(); await new Promise(resolve => server.close(resolve));}
})().catch(e => {console.error(e); process.exitCode = 1;});
