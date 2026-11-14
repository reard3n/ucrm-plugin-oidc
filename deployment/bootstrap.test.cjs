'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const {PROFILES, LOGIN_SCRIPT_TAG, sha256, instrument, instrumentLoginPage, selectBundle} = require('./bootstrap.cjs');
const sample = Buffer.from('before\nSTART_HAPI\nafter');
const fixture = {hash: sha256(sample), seam: 'START_HAPI', insertion: 'START_HAPI;INSTALL_ASYNC'};
test('unknown native bytes cannot be instrumented', () => {
  assert.throws(() => instrument(Buffer.from('changed'), fixture), /unsupported_native_hash/);
});
test('matching hash alone cannot admit absent or duplicate startup seam', () => {
  for (const value of ['other', 'START_HAPI START_HAPI']) {
    const bytes = Buffer.from(value);
    assert.throws(() => instrument(bytes, {...fixture, hash: sha256(bytes)}), /unsupported_native_seam/);
  }
});
test('instrumentation retains all native bytes outside the one seam', () => {
  assert.equal(instrument(sample, fixture).toString(), 'before\nSTART_HAPI;INSTALL_ASYNC\nafter');
});
test('disabled startup restores exactly known generated bundle', () => {
  const generated = instrument(sample, fixture);
  assert.deepEqual(selectBundle(generated, sample, generated, false), sample);
  assert.deepEqual(selectBundle(sample, sample, generated, true), generated);
  assert.throws(() => selectBundle(Buffer.from('unknown'), sample, generated, false), /unrecognized_runtime_bundle/);
});
test('both audited profiles preserve native startup and immutable message factories', () => {
  assert.deepEqual(PROFILES['uisp-2.4.220'].command, ['index.js']);
  assert.deepEqual(PROFILES['uisp-3.1.73'].command, ['api.sh']);
  assert.match(PROFILES['uisp-3.1.73'].insertion, /userLoginSuccess:f7,userLoginFailed:rpn/);
  for (const p of Object.values(PROFILES)) {
    assert.match(p.image, /^ubnt\/unms@sha256:[a-f0-9]{64}$/);
    assert.match(p.insertion, /Promise.resolve\(\).then/);
    assert.match(p.insertion, /\.catch\(/);
  }
});
test('login script insertion preserves original page bytes and only adds the fixed same-origin tag', () => {
  const original = Buffer.from('<head><script type="module" src="/native.js"></script></head>\n<body>native</body>\n');
  const profile = {publicIndexHash: sha256(original)};
  const generated = instrumentLoginPage(original, profile);
  assert.equal(generated.toString().replace(LOGIN_SCRIPT_TAG, ''), original.toString());
  assert.equal(generated.toString().split(LOGIN_SCRIPT_TAG).length, 2);
  assert.deepEqual(selectBundle(generated, original, generated, false), original);
});
test('unknown, repeated, absent and already patched login-page sources fail closed', () => {
  assert.throws(() => instrumentLoginPage(Buffer.from('unknown'), {publicIndexHash: 'a'.repeat(64)}), /unsupported_login_page_hash/);
  for (const value of ['native', '<body></body></body>', LOGIN_SCRIPT_TAG + '</body>']) {
    const bytes = Buffer.from(value);
    assert.throws(() => instrumentLoginPage(bytes, {publicIndexHash: sha256(bytes)}), /unsupported_login_page_seam/);
  }
});
