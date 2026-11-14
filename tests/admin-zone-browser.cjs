'use strict';
// Native-hook browser contract; every HTTP response below is synthetic.
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const assert = require('node:assert/strict');
const pw = require(process.env.OIDC229_PLAYWRIGHT_MODULE || 'playwright');
const script = fs.readFileSync(path.join(__dirname, '../plugin/public/admin-zone.js'), 'utf8');
const origin = 'https://crm.example.test';
const entry = '/crm/_plugins/ucrm-oidc/public.php';
const route = '/crm/system/plugins/3/configuration';
const form = '<form id="plugin-configuration-form" method="post" action="' + route + '"><input name="plugin_configuration[configuration][oidcEnabled]" type="checkbox"><select name="executionPeriod"><option>5 minutes</option></select><input name="native_csrf" type="hidden" value="fixture"><button>Save</button></form>';
const results = [];
let active = 'launch';
(async () => {
  const browser = await pw.chromium.launch({channel: 'chrome', headless: true});
  try {
    for (const item of [
      {name: 'own native settings embeds existing protected form without modifying native form', pathname: route, embed: true},
      {name: 'other plugin configuration never receives the embed', pathname: '/crm/system/plugins/4/configuration', embed: false},
      {name: 'native plugin list does not fetch or embed settings', pathname: '/crm/system/plugins', embed: false, fetch: false},
      {name: 'native public wrapper does not recursively embed', pathname: '/crm/system/plugins/3/public', embed: false, fetch: false},
      {name: 'permission denied preserves native configuration unchanged', pathname: route, embed: false, status: 403},
      {name: 'missing native checkbox leaves unrelated forms untouched', pathname: route, embed: false, marker: false, fetch: false},
      {name: 'redirected protected page fails closed', pathname: route, embed: false, status: 302},
      {name: 'duplicate plugin identity links fail closed', pathname: route, embed: false, duplicate: true},
    ]) {
      active = item.name;
      const ctx = await browser.newContext();
      let requests = 0;
      const errors = [];
      await ctx.route('**/*', request => {
        const url = new URL(request.request().url());
        assert.equal(url.origin, origin);
        if (url.pathname.endsWith('/admin-zone.js')) return request.fulfill({contentType: 'text/javascript', body: script});
        if (url.pathname === entry) {
          requests++;
          return request.fulfill({status: item.status || 200, contentType: 'text/html', headers: item.status === 302 ? {Location: '/nms/login'} : {},
            body: '<!doctype html><style>html,body{height:100%;margin:0}main{height:1300px;padding:28px;box-sizing:border-box}</style><body><main class="oidc-container"><h1>OpenID Connect</h1>'
              + `<a href="${route}">Native configuration</a>`.repeat(item.duplicate ? 2 : 1) + '<input name="issuer"><input name="clientSecret" value=""></main></body>'});
        }
        if (url.pathname === item.pathname) return request.fulfill({contentType: 'text/html', body: '<!doctype html><head><script defer src="/crm/_plugins/ucrm-oidc/public/admin-zone.js"></script></head><body><div id="configuration_form">'
          + (item.marker === false ? form.replace('oidcEnabled', 'unrelated') : form.replaceAll(route, item.pathname)) + '</div></body>'});
        return request.abort();
      });
      const page = await ctx.newPage();
      page.on('pageerror', () => errors.push('error'));
      await page.goto(origin + item.pathname);
      const initial = item.marker === false ? form.replace('oidcEnabled', 'unrelated') : form.replaceAll(route, item.pathname);
      if (item.embed) {
        await page.locator('#ucrm-oidc-provider-settings iframe').waitFor();
        await page.frameLocator('#ucrm-oidc-provider-settings iframe').locator('input[name="issuer"]').waitFor();
        assert.equal(await page.locator('#ucrm-oidc-provider-settings iframe').getAttribute('src'), entry + '?action=admin');
        assert.equal(await page.locator('#ucrm-oidc-provider-settings iframe').getAttribute('referrerpolicy'), 'no-referrer');
        assert.equal(await page.locator('#plugin-configuration-form #ucrm-oidc-provider-settings').count(), 0);
        await page.addScriptTag({content: script});
        assert.equal(await page.locator('#ucrm-oidc-provider-settings').count(), 1);
        await page.waitForTimeout(100);
        assert.ok(await page.locator('#ucrm-oidc-provider-settings iframe').evaluate(node => parseInt(node.style.height, 10)) >= 1300);
        assert.ok(await page.locator('#ucrm-oidc-provider-settings iframe').evaluate(node => node.contentDocument.documentElement.scrollHeight <= node.clientHeight + 1));
        await page.frameLocator('#ucrm-oidc-provider-settings iframe').locator('main').evaluate(node => { node.style.height = '1900px'; });
        await page.waitForFunction(() => document.querySelector('#ucrm-oidc-provider-settings iframe').clientHeight === 1900);
        await page.frameLocator('#ucrm-oidc-provider-settings iframe').locator('main').evaluate(node => { node.style.height = '700px'; });
        await page.waitForFunction(() => document.querySelector('#ucrm-oidc-provider-settings iframe').clientHeight === 700);
        await page.waitForTimeout(150);
        assert.equal(await page.locator('#ucrm-oidc-provider-settings iframe').evaluate(node => node.clientHeight), 700);
        assert.equal(requests, 2);
      } else {
        await page.waitForTimeout(150);
        assert.equal(await page.locator('#ucrm-oidc-provider-settings').count(), 0);
        if (item.fetch === false) assert.equal(requests, 0);
      }
      assert.equal(await page.locator('#plugin-configuration-form').evaluate(node => node.outerHTML), initial);
      assert.deepEqual(errors, []);
      results.push({test: active, status: 'passed'});
      await ctx.close();
    }
    process.stdout.write(JSON.stringify({passed: results.length, tests: results}) + '\n');
  } finally { await browser.close(); }
})().catch(() => { process.stderr.write(JSON.stringify({test: active, status: 'failed'}) + '\n'); process.exitCode = 1; });
