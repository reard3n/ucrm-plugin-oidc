'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { EventEmitter } = require('node:events');
const { createNativeHandler } = require('../native.cjs');
const { createProtocol, createReceipts, derive, sign } = require('../protocol.cjs');
const { install, PROFILES, CONFIG_PATH, KEY_PATH } = require('../index.cjs');
const UUID = () => crypto.randomUUID();
const HEX = () => crypto.randomBytes(32).toString('hex');
const master = Buffer.alloc(32, 0xab);
const receiptKey = derive(master, 'adapter-receipt');
const transportKey = derive(master, 'adapter-transport');
const audit = { remoteAddress: '192.0.2.20', userAgent: 'native-adapter-unit' };

function fixture(options = {}) {
  const ctx = { time: 1800000000000, plugin: { id: 7, name: 'ucrm-oidc', enabled: true },
    config: Buffer.from('{"oidcEnabled":true}'), users: new Map(), records: new Map(),
    calls: { created: 0, challenges: 0, injected: [], removed: [], success: [], failure: [], attempts: [] },
    roles: [{ id: UUID(), name: 'Read-only' }], settings: { ucrmEnabled: true }, epoch: HEX() };
  const user = { id: UUID(), username: 'staff', email: 'staff@oidc229.example.com', role: 'guest',
    ucrmRole: ctx.roles[0].id, enabled: true, forceChangePassword: false, homeScreen: '/crm',
    totpAuthEnabled: false, totpAuthSecretDeciphered: true, sessionTimeout: 60000, keepMeSignedIn: true,
    password: 'must-not-be-returned', totpAuthSecret: 'must-not-be-returned', ...options.user };
  ctx.user = user;
  ctx.users.set(user.id, user);
  function record(type, user, data = null) {
    const value = { id: UUID(), type, userId: user.id, token: UUID(), ucrmSessionId: type === 'api' ? UUID() : null,
      createdAt: new Date(ctx.time), expiresAt: new Date(ctx.time + (type === 'api' ? 60000 : (ctx.challengeTtl ?? 180000))), data };
    ctx.records.set(value.token, value);
    return value;
  }
  function validate(value, type) {
    if (!value || value.type !== type || value.expiresAt.getTime() <= ctx.time || !ctx.users.get(value.userId)?.enabled) return { valid: false };
    const user = ctx.users.get(value.userId);
    return { valid: true, credentials: { userId: user.id, role: user.role }, artifacts: {
      token: value.token, tokenId: value.id, ucrmSessionId: value.ucrmSessionId, data: value.data } };
  }
  const auth = {
    async createSessionToken({ cmUser, data }) { ctx.calls.created++; const value = record('api', cmUser, data); return { token: value.token, ucrmSessionId: value.ucrmSessionId }; },
    async createTwoFactorToken(user) { ctx.calls.challenges++; return record('two-factor', user).token; },
    async validateApiToken(token) { return validate(ctx.records.get(token), 'api'); },
    async validateTwoFactorToken(token) { return validate(ctx.records.get(token), 'two-factor'); },
    async validateSessionId(sessionId) { return validate([...ctx.records.values()].find(r => r.ucrmSessionId === sessionId), 'api'); },
    async removeToken(token) { ctx.calls.removed.push(token); ctx.records.delete(token); },
    async removeTokenBySessionId(sessionId) { ctx.calls.removed.push(sessionId); for (const [token, row] of ctx.records) if (row.ucrmSessionId === sessionId) ctx.records.delete(token); }
  };
  const messages = { userLoginSuccess: data => ({ success: data }), userLoginFailed: data => ({ failure: data }) };
  const server = { events: new EventEmitter(), plugins: {
    auth, user: { getUser(id) { return { toPromise: async () => ctx.users.get(id) || null }; } },
    settings: { async getSettings() { return ctx.settings; } },
    bruteForce: { async addAttemptForLogin(...args) { ctx.calls.attempts.push(args); if (ctx.admissionHook) await ctx.admissionHook(); },
      async userLoginSuccess(...args) { ctx.calls.success.push(args); } },
    messageHub: { messages, async publish(event) { if (event.failure) ctx.calls.failure.push(event.failure); } },
    dal: { crmRepository: { db: { async oneOrNone(sql, params) { assert.equal(sql, 'SELECT id, name, enabled FROM ucrm.plugin WHERE name = $1'); assert.deepEqual(params, ['ucrm-oidc']); return ctx.plugin; } },
      async findAllRoles() { return ctx.roles; } },
      userRepository: { async findByEmail(email) { return [...ctx.users.values()].filter(u => u.email === email); } },
      tokenRepository: { async findTokenById(id, type, { userId }) {
        const row = [...ctx.records.values()].find(r => r.id === id && r.type === type && r.userId === userId && ctx.users.get(userId)?.enabled && r.expiresAt.getTime() > ctx.time);
        return row ? { id: row.id, token: row.token, type: row.type, createdAt: row.createdAt,
          expiresAt: row.expiresAt, ucrmSessionId: row.ucrmSessionId, user: { userId: row.userId } } : null;
      } } }
  }, async inject(request) {
    ctx.calls.injected.push(request);
    assert.equal(request.method, 'POST');
    assert.equal(request.url, '/nms/api/v2.1/user/login/totpauth');
    assert.equal(request.remoteAddress, audit.remoteAddress);
    assert.deepEqual(request.headers, { 'user-agent': audit.userAgent });
    assert.equal(Object.hasOwn(request, 'auth'), false);
    if (request.payload.verificationCode !== '123456') return { statusCode: 403, headers: {} };
    const checked = await auth.validateTwoFactorToken(request.payload.token);
    if (!checked.valid) return { statusCode: 401, headers: {} };
    await auth.removeToken(request.payload.token);
    const pair = await auth.createSessionToken({ cmUser: ctx.users.get(checked.credentials.userId) });
    return { statusCode: 200, headers: { 'x-auth-token': pair.token } };
  } };
  ctx.server = server;
  ctx.handler = createNativeHandler({ server, profile: PROFILES['uisp-2.4.220'], receiptKey,
    epoch: ctx.epoch, now: () => ctx.time, readConfig: async () => ctx.config, ...options.handler });
  ctx.status = () => ctx.handler({ operation: 'status' });
  ctx.body = async (operation, fields = {}) => {
    const status = await ctx.status();
    const defaults = { nativeUserId: user.id, serverEpoch: status.serverEpoch, configRevision: status.configRevision };
    if (operation === 'issue') Object.assign(defaults, { transactionId: HEX(), assertedAt: ctx.time / 1000, expiresAt: ctx.time / 1000 + 60, audit });
    return { operation, ...defaults, ...fields };
  };
  ctx.issue = async fields => ctx.handler(await ctx.body('issue', fields));
  return ctx;
}
async function rejectsCode(promise, code) { await assert.rejects(promise, error => error.code === code); }
function envelope(body, extra = {}) {
  const value = { v: 2, caller: 'ucrm-oidc', keyId: 'installation-v1', at: 1800000000,
    nonce: HEX(), body: Buffer.from(JSON.stringify(body)).toString('base64url'), ...extra };
  value.mac = sign(value, transportKey);
  return Buffer.from(JSON.stringify(value));
}

test('transport HKDF separates cleanup and service keys; deterministic envelope interoperable', () => {
  assert.notDeepEqual(receiptKey, transportKey);
  assert.equal(transportKey.length, 32);
  assert.equal(transportKey.toString('hex'), 'be4bcd812e1670e9bdc75c297d7598c539a0923fe38049eb0e71c636323490a1');
  const value = JSON.parse(envelope({ operation: 'status' }, { nonce: 'cd'.repeat(32) }));
  assert.equal(value.mac, '50ed372ddeb2ffe2d28e926712e4d36f9b47cac57e4bba11b0cf9406bea037e0');
  assert.equal(value.body, 'eyJvcGVyYXRpb24iOiJzdGF0dXMifQ');
});
test('wire nonce reservation excludes simultaneous requests before handler await', async () => {
  let release, count = 0;
  const pending = new Promise(resolve => { release = resolve; });
  const dispatch = createProtocol({ key: transportKey, now: () => 1800000000000, handler: async () => { count++; await pending; return {}; } });
  const frame = envelope({ operation: 'status' });
  const first = dispatch(frame);
  assert.equal((await dispatch(frame)).error.code, 'REPLAY');
  release();
  assert.equal((await first).ok, true);
  assert.equal(count, 1);
});
test('wire wrong MAC, caller, version, stale time, malformed encoding and oversized frame deny', async () => {
  let called = 0;
  const dispatch = createProtocol({ key: transportKey, now: () => 1800000000000, handler: async () => { called++; } });
  for (const fields of [{ caller: 'other' }, { v: 1 }, { at: 1800000031 }, { at: 1799999969 }, { body: '====' }]) {
    assert.equal((await dispatch(envelope({}, fields))).ok, false);
  }
  const bad = JSON.parse(envelope({})); bad.mac = '00'.repeat(32);
  assert.equal((await dispatch(Buffer.from(JSON.stringify(bad)))).error.code, 'AUTHENTICATION_FAILED');
  assert.equal((await dispatch(Buffer.alloc(16385))).error.code, 'BAD_REQUEST');
  assert.equal(called, 0);
});
test('bounded nonce cache fails closed without evicting live protection', async () => {
  const dispatch = createProtocol({ key: transportKey, now: () => 1800000000000, nonceLimit: 1, handler: async () => ({}) });
  assert.equal((await dispatch(envelope({}))).ok, true);
  assert.equal((await dispatch(envelope({}))).error.code, 'BUSY');
});
test('exact email resolves existing restricted staff; projection contains no native secrets', async () => {
  const ctx = fixture();
  const status = await ctx.status();
  const body = { operation: 'resolve', email: ctx.user.email, serverEpoch: status.serverEpoch, configRevision: status.configRevision };
  const result = await ctx.handler(body);
  assert.equal(result.user.id, ctx.user.id);
  assert.equal(JSON.stringify(result).includes('must-not-be-returned'), false);
  await rejectsCode(ctx.handler({ ...body, email: ctx.user.email.toUpperCase() }), 'ADMISSION_DENIED');
  ctx.users.set(UUID(), { ...ctx.user, id: UUID(), enabled: false });
  await rejectsCode(ctx.handler(body), 'ADMISSION_DENIED');
});
test('administrator and CRM-only staff admitted without role remapping', async () => {
  for (const role of ['superadmin', 'admin', 'anonymous', 'installer', 'guest']) {
    const ctx = fixture({ user: { role } });
    const result = await ctx.issue();
    assert.equal(result.user.role, role);
    assert.equal(result.user.ucrmRole, ctx.user.ucrmRole);
    assert.equal(result.cookieTtlMs, 60000);
    assert.equal(result.createdAt, 1800000000);
  }
});
test('unknown, customer-only, disabled, forced-reset, NMS-only and missing group deny issuance', async () => {
  for (const changes of [{ enabled: false }, { forceChangePassword: true }, { ucrmRole: null }, { ucrmRole: UUID() }, { role: 'customer' }]) {
    const ctx = fixture({ user: changes });
    await rejectsCode(ctx.issue(), 'ADMISSION_DENIED');
    assert.equal(ctx.calls.created, 0);
  }
  const ctx = fixture();
  await rejectsCode(ctx.issue({ nativeUserId: UUID() }), 'ADMISSION_DENIED');
  ctx.settings.ucrmEnabled = false;
  await rejectsCode(ctx.issue(), 'ADMISSION_DENIED');
});
test('native state reread after asynchronous admission prevents disabled issuance', async () => {
  const ctx = fixture();
  ctx.admissionHook = async () => { ctx.user.enabled = false; };
  await rejectsCode(ctx.issue(), 'ADMISSION_DENIED');
  assert.equal(ctx.calls.created, 0);
  assert.equal(ctx.calls.failure.length, 1);
});
test('configuration, native plugin, epoch and short assertion freshness gates', async () => {
  const ctx = fixture();
  const body = await ctx.body('issue');
  await rejectsCode(ctx.handler({ ...body, serverEpoch: HEX() }), 'STALE_EPOCH');
  await rejectsCode(ctx.handler({ ...body, configRevision: HEX() }), 'CONFIG_CHANGED');
  await rejectsCode(ctx.handler({ ...body, expiresAt: body.assertedAt }), 'BAD_REQUEST');
  await rejectsCode(ctx.handler({ ...body, assertedAt: body.assertedAt - 70, expiresAt: body.expiresAt - 70 }), 'ASSERTION_EXPIRED');
  ctx.plugin.enabled = false;
  await rejectsCode(ctx.handler(body), 'PLUGIN_INACTIVE');
  ctx.plugin.enabled = true;
  ctx.config = Buffer.from('{"oidcEnabled":false}');
  const disabled = await ctx.body('issue');
  await rejectsCode(ctx.handler(disabled), 'OIDC_DISABLED');
  ctx.config = Buffer.from('{"oidcEnabled":"true"}');
  assert.equal((await ctx.status()).configRevision, null);
});
test('issue transaction cannot be replayed with a new wire nonce or concurrently', async () => {
  const ctx = fixture();
  const body = await ctx.body('issue');
  const results = await Promise.allSettled([ctx.handler(body), ctx.handler(body)]);
  assert.equal(results.filter(r => r.status === 'fulfilled').length, 1);
  assert.equal(results.find(r => r.status === 'rejected').reason.code, 'TRANSACTION_USED');
  assert.equal(ctx.calls.created, 1);
});
test('native failure after issuance deletes only created pair', async () => {
  const ctx = fixture();
  const original = ctx.server.plugins.auth.createSessionToken;
  ctx.server.plugins.auth.createSessionToken = async value => { const pair = await original(value); ctx.user.enabled = false; return pair; };
  await rejectsCode(ctx.issue(), 'ADMISSION_DENIED');
  assert.equal(ctx.records.size, 0);
  assert.equal(ctx.calls.removed.length, 1);
});
test('native nested token metadata ownership is mandatory and mismatch cleans the pair', async () => {
  const ctx = fixture();
  ctx.server.plugins.dal.tokenRepository.findTokenById = async () => ({ userId: ctx.user.id,
    user: { userId: UUID() }, createdAt: new Date(ctx.time) });
  await rejectsCode(ctx.issue(), 'ADMISSION_DENIED');
  assert.equal(ctx.records.size, 0);
});
test('receipts authorize only exact artifact/user/kind and survive handler restart and disablement', async () => {
  const ctx = fixture();
  const pair = await ctx.issue();
  const body = { operation: 'revoke', nativeUserId: ctx.user.id, kind: 'session', artifact: pair.ucrmSessionId, receipt: pair.receipt, serverEpoch: ctx.epoch };
  for (const edit of [{ artifact: UUID() }, { nativeUserId: UUID() }, { kind: 'mfa' }]) await rejectsCode(ctx.handler({ ...body, ...edit }), 'RECEIPT_INVALID');
  ctx.user.enabled = false;
  ctx.plugin.enabled = false;
  ctx.config = Buffer.from('{}');
  const newEpoch = HEX();
  const restart = createNativeHandler({ server: ctx.server, profile: PROFILES['uisp-2.4.220'], readConfig: async () => ctx.config,
    receiptKey, epoch: newEpoch, now: () => ctx.time });
  assert.deepEqual(await restart({ ...body, serverEpoch: newEpoch }), { kind: 'revoked' });
  assert.equal(ctx.records.size, 0);
  assert.deepEqual(await restart({ ...body, serverEpoch: newEpoch }), { kind: 'revoked' });
});
test('MFA issues no full pair, injects unchanged native route, rejects wrong code and challenge replay', async () => {
  const ctx = fixture({ user: { totpAuthEnabled: true } });
  const request = await ctx.body('issue');
  const challenge = await ctx.handler(request);
  assert.equal(challenge.kind, 'mfa');
  assert.equal(challenge.expiresAt, 1800000180);
  assert.equal(challenge.token, undefined);
  assert.equal(challenge.ucrmSessionId, undefined);
  assert.equal(ctx.calls.created, 0);
  const completion = { operation: 'complete-mfa', nativeUserId: ctx.user.id, transactionId: request.transactionId,
    twoFactorToken: challenge.twoFactorToken, receipt: challenge.receipt, verificationCode: '000000',
    serverEpoch: ctx.epoch, configRevision: request.configRevision, audit };
  await rejectsCode(ctx.handler(completion), 'MFA_INVALID');
  assert.equal(ctx.calls.created, 0);
  const full = await ctx.handler({ ...completion, verificationCode: '123456' });
  assert.equal(full.kind, 'session');
  assert.equal(full.user.id, ctx.user.id);
  assert.equal(ctx.calls.created, 1);
  await rejectsCode(ctx.handler({ ...completion, verificationCode: '123456' }), 'MFA_EXPIRED');
  // Native injected handler owns the success counter/audit; adapter does not duplicate it.
  assert.equal(ctx.calls.success.length, 0);
});
test('MFA disabled user, expired challenge, native legacy secret and cross-user substitution fail closed', async () => {
  const legacy = fixture({ user: { totpAuthEnabled: true, totpAuthSecretDeciphered: false } });
  await rejectsCode(legacy.issue(), 'MFA_LOCAL_LOGIN_REQUIRED');
  assert.equal(legacy.calls.challenges, 0);
  const ctx = fixture({ user: { totpAuthEnabled: true } });
  const request = await ctx.body('issue');
  const challenge = await ctx.handler(request);
  const body = { operation: 'complete-mfa', nativeUserId: ctx.user.id, transactionId: request.transactionId,
    twoFactorToken: challenge.twoFactorToken, receipt: challenge.receipt, verificationCode: '123456',
    serverEpoch: ctx.epoch, configRevision: request.configRevision, audit };
  await rejectsCode(ctx.handler({ ...body, nativeUserId: UUID() }), 'RECEIPT_INVALID');
  ctx.user.enabled = false;
  await rejectsCode(ctx.handler(body), 'ADMISSION_DENIED');
  ctx.user.enabled = true;
  ctx.time += 181000;
  await rejectsCode(ctx.handler(body), 'MFA_EXPIRED');
  assert.equal(ctx.calls.injected.length, 0);
});
test('short native MFA challenge expiry never shortens issue replay reservation', async () => {
  const ctx = fixture({ user: { totpAuthEnabled: true } });
  ctx.challengeTtl = 1000;
  const body = await ctx.body('issue');
  await ctx.handler(body);
  ctx.time += 2000;
  await rejectsCode(ctx.handler(body), 'TRANSACTION_USED');
  assert.equal(ctx.calls.challenges, 1);
});
test('unexpected native success without token cleans exact returned cookie artifact', async () => {
  const ctx = fixture({ user: { totpAuthEnabled: true } });
  const request = await ctx.body('issue');
  const challenge = await ctx.handler(request);
  const orphan = await ctx.server.plugins.auth.createSessionToken({ cmUser: ctx.user });
  ctx.server.inject = async () => ({ statusCode: 200, headers: { 'set-cookie': ['nms-session=' + orphan.ucrmSessionId + '; HttpOnly'] } });
  const body = { operation: 'complete-mfa', nativeUserId: ctx.user.id, transactionId: request.transactionId,
    twoFactorToken: challenge.twoFactorToken, receipt: challenge.receipt, verificationCode: '123456',
    serverEpoch: ctx.epoch, configRevision: request.configRevision, audit };
  await rejectsCode(ctx.handler(body), 'NATIVE_UNAVAILABLE');
  assert.equal((await ctx.server.plugins.auth.validateApiToken(orphan.token)).valid, false);
});
test('describe recognizes NMS-only existing caller without granting OIDC eligibility', async () => {
  const ctx = fixture({ user: { ucrmRole: null } });
  const pair = await ctx.server.plugins.auth.createSessionToken({ cmUser: ctx.user });
  const result = await ctx.handler({ operation: 'describe-caller', callerSessionId: pair.ucrmSessionId, audit, serverEpoch: ctx.epoch });
  assert.equal(result.nativeUserId, ctx.user.id);
  assert.equal(result.ucrmRole, null);
  assert.equal(result.source, 'native-unattributed');
  assert.equal(result.createdAt, 1800000000);
  assert.equal(result.token, undefined);
  await rejectsCode(ctx.issue(), 'ADMISSION_DENIED');
});
test('describe adapter marker is provenance only; invalid caller denies', async () => {
  const ctx = fixture();
  const pair = await ctx.issue();
  const body = { operation: 'describe-caller', callerSessionId: pair.ucrmSessionId, audit, serverEpoch: ctx.epoch };
  assert.equal((await ctx.handler(body)).source, 'adapter');
  await rejectsCode(ctx.handler({ ...body, callerSessionId: UUID() }), 'ADMISSION_DENIED');
});
test('strict schema rejects caller-supplied permissions and audit control characters', async () => {
  const ctx = fixture();
  await rejectsCode(ctx.issue({ role: 'superadmin' }), 'BAD_REQUEST');
  await rejectsCode(ctx.issue({ audit: { remoteAddress: '127.0.0.1', userAgent: 'x\r\ny' } }), 'BAD_REQUEST');
  assert.equal(ctx.calls.created, 0);
});
test('bootstrap disabled or missing contract fails closed without throwing into native server', async () => {
  assert.deepEqual(await install({}, { env: {} }), { enabled: false, reason: 'DISABLED' });
  const log = console.error; let safe = [];
  console.error = value => safe.push(value);
  try {
    const value = await install({}, { env: { UCRM_OIDC_ADAPTER_ENABLED: '1' }, readRegular: async () => { throw new Error('SECRET DO NOT LOG'); } });
    assert.equal(value.enabled, false);
    assert.equal(JSON.stringify(safe).includes('SECRET'), false);
  } finally { console.error = log; }
});
test('latest profile accepts absence of retired legacy MFA field and uses supplied native message factories', async () => {
  const ctx = fixture({ user: { totpAuthEnabled: true, totpAuthSecretDeciphered: undefined } });
  const nativeMessages = ctx.server.plugins.messageHub.messages;
  delete ctx.server.plugins.messageHub.messages;
  const handler = createNativeHandler({ server: ctx.server, profile: PROFILES['uisp-3.1.73'], receiptKey,
    nativeMessages, readConfig: async () => ctx.config, epoch: ctx.epoch, now: () => ctx.time });
  const body = await ctx.body('issue');
  assert.equal((await handler(body)).kind, 'mfa');
});
