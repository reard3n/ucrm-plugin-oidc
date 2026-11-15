'use strict';

const crypto = require('node:crypto');
const net = require('node:net');
const { AdapterError, HEX, createReceipts, exactKeys, fail, object } = require('./protocol.cjs');
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const PLUGIN_SQL = 'SELECT id, name, enabled FROM ucrm.plugin WHERE name = $1';
const PLUGIN_NAME = 'ucrm-oidc';
const NATIVE_ROLES = new Set(['superadmin', 'admin', 'guest', 'anonymous', 'installer']);
const SCHEMAS = {
  status: [],
  resolve: ['email', 'serverEpoch', 'configRevision'],
  inspect: ['nativeUserId', 'serverEpoch', 'configRevision'],
  'describe-caller': ['callerSessionId', 'audit', 'serverEpoch'],
  issue: ['nativeUserId', 'transactionId', 'assertedAt', 'expiresAt', 'serverEpoch', 'configRevision', 'audit'],
  'complete-mfa': ['nativeUserId', 'transactionId', 'twoFactorToken', 'receipt', 'verificationCode', 'serverEpoch', 'configRevision', 'audit'],
  revoke: ['nativeUserId', 'kind', 'artifact', 'receipt', 'serverEpoch']
};

function createNativeHandler({ server, readConfig, receiptKey, profile, nativeMessages,
  epoch = crypto.randomBytes(32).toString('hex'), now = Date.now, attemptLimit = 4096, canaryEmailDomain = null }) {
  const { auth, user: users, settings, bruteForce, messageHub, dal } = server.plugins;
  const db = dal?.crmRepository?.db;
  const messages = nativeMessages || messageHub?.messages;
  const methods = ['createSessionToken', 'validateApiToken', 'validateSessionId',
    'removeToken', 'removeTokenBySessionId'];
  if (!auth || methods.some(k => typeof auth[k] !== 'function') || typeof users?.getUser !== 'function' ||
      typeof settings?.getSettings !== 'function' || typeof db?.oneOrNone !== 'function' ||
      typeof dal?.userRepository?.findByEmail !== 'function' || typeof dal?.crmRepository?.findAllRoles !== 'function' ||
      typeof dal?.tokenRepository?.findTokenById !== 'function' || typeof server.inject !== 'function' ||
      typeof messageHub?.publish !== 'function' || typeof messages?.userLoginSuccess !== 'function' ||
      typeof messages?.userLoginFailed !== 'function' ||
      ['addAttemptForLogin', 'userLoginSuccess'].some(k => typeof bruteForce?.[k] !== 'function')) throw new Error('Native contract unavailable');
  const receipts = createReceipts(receiptKey);
  const attempts = new Map();

  function parse(body) {
    if (!object(body) || !Object.hasOwn(SCHEMAS, body.operation) || !exactKeys(body, ['operation', ...SCHEMAS[body.operation]])) fail('BAD_REQUEST');
    for (const key of ['nativeUserId', 'callerSessionId', 'twoFactorToken', 'artifact']) {
      if (Object.hasOwn(body, key) && (typeof body[key] !== 'string' || !UUID.test(body[key]))) fail('BAD_REQUEST');
    }
    for (const key of ['serverEpoch', 'configRevision', 'transactionId']) {
      if (Object.hasOwn(body, key) && (typeof body[key] !== 'string' || !HEX.test(body[key]))) fail('BAD_REQUEST');
    }
    if (Object.hasOwn(body, 'audit') && (!exactKeys(body.audit, ['remoteAddress', 'userAgent']) ||
      typeof body.audit.remoteAddress !== 'string' || !net.isIP(body.audit.remoteAddress) ||
      typeof body.audit.userAgent !== 'string' || body.audit.userAgent.length > 256 || /[\r\n\x00]/.test(body.audit.userAgent))) fail('BAD_REQUEST');
    if (body.operation === 'resolve' && (typeof body.email !== 'string' || body.email.length < 3 || body.email.length > 320 ||
      /[\s\x00-\x1f\x7f]/.test(body.email) || !body.email.includes('@'))) fail('BAD_REQUEST');
    if (body.operation === 'revoke' && !['session', 'mfa'].includes(body.kind)) fail('BAD_REQUEST');
    if (body.operation === 'complete-mfa' && (typeof body.verificationCode !== 'string' || !/^\d{6}$/.test(body.verificationCode))) fail('BAD_REQUEST');
    if (body.operation === 'issue' && (!Number.isSafeInteger(body.assertedAt) || !Number.isSafeInteger(body.expiresAt) ||
      body.expiresAt <= body.assertedAt || body.expiresAt - body.assertedAt > 60)) fail('BAD_REQUEST');
  }
  async function pluginRow() {
    const row = await db.oneOrNone(PLUGIN_SQL, [PLUGIN_NAME]);
    if (row && (!Number.isSafeInteger(row.id) || row.id < 1 || row.name !== PLUGIN_NAME || typeof row.enabled !== 'boolean')) fail('NATIVE_UNAVAILABLE');
    return row;
  }
  async function state(row = undefined) {
    row = row === undefined ? await pluginRow() : row;
    let bytes, config;
    try {
      bytes = await readConfig();
      if (!Buffer.isBuffer(bytes) || bytes.length < 1 || bytes.length > 65536) throw new Error();
      config = JSON.parse(bytes.toString('utf8'));
      if (!object(config) || typeof config.oidcEnabled !== 'boolean') throw new Error();
    } catch { return { pluginEnabled: row?.enabled === true, enabled: false, revision: null }; }
    return { pluginEnabled: row?.enabled === true, enabled: row?.enabled === true && config.oidcEnabled,
      revision: crypto.createHash('sha256').update(bytes).digest('hex') };
  }
  function epochCheck(body) { if (body.serverEpoch !== epoch) fail('STALE_EPOCH'); }
  function configured(body, value) {
    epochCheck(body);
    if (!value.pluginEnabled) fail('PLUGIN_INACTIVE');
    if (!value.revision) fail('CONFIG_UNAVAILABLE');
    if (body.configRevision !== value.revision) fail('CONFIG_CHANGED');
    if (!value.enabled) fail('OIDC_DISABLED');
  }
  async function eligible(nativeUserId) {
    const user = await users.getUser(nativeUserId).toPromise();
    const app = await settings.getSettings();
    if (!user || user.id !== nativeUserId || user.enabled !== true || user.forceChangePassword !== false ||
        !NATIVE_ROLES.has(user.role) || app.ucrmEnabled !== true || typeof user.username !== 'string' || typeof user.email !== 'string') fail('ADMISSION_DENIED');
    if (canaryEmailDomain && !user.email.endsWith('@' + canaryEmailDomain)) fail('ADMISSION_DENIED');
    if (user.role !== 'superadmin') {
      const roles = await dal.crmRepository.findAllRoles();
      if (typeof user.ucrmRole !== 'string' || !Array.isArray(roles) || !roles.some(r => r.id === user.ucrmRole)) fail('ADMISSION_DENIED');
    }
    return user;
  }
  function projection(user) {
    return { id: user.id, username: user.username, email: user.email, role: user.role,
      ucrmRole: user.ucrmRole ?? null, homeScreen: user.homeScreen, totpAuthEnabled: !!user.totpAuthEnabled,
      sessionTimeout: user.sessionTimeout, keepMeSignedIn: !!user.keepMeSignedIn };
  }
  async function tokenMetadata(checked, type = 'api') {
    if (!checked?.valid || !UUID.test(checked.credentials?.userId ?? '') || !UUID.test(checked.artifacts?.tokenId ?? '')) fail('ADMISSION_DENIED');
    const row = await dal.tokenRepository.findTokenById(checked.artifacts.tokenId, type, { userId: checked.credentials.userId });
    // Native metadata mapper associates ownership as user.userId; validator
    // credentials use the separate flat userId contract.
    if (!row || row.user?.userId !== checked.credentials.userId) fail('ADMISSION_DENIED');
    return row;
  }
  function seconds(value) {
    const milliseconds = value instanceof Date ? value.getTime() : Date.parse(value);
    if (!Number.isFinite(milliseconds)) fail('NATIVE_UNAVAILABLE');
    return Math.floor(milliseconds / 1000);
  }
  function nativeError(error) {
    if (error instanceof AdapterError) return error;
    if (error?.output?.statusCode === 429) return new AdapterError('RATE_LIMITED');
    return new AdapterError('NATIVE_UNAVAILABLE');
  }
  async function checkedPair(pair, user, audit) {
    const api = await auth.validateApiToken(pair.token, audit.remoteAddress);
    const cookie = await auth.validateSessionId(pair.ucrmSessionId, audit.remoteAddress);
    if (!api?.valid || !cookie?.valid || api.credentials?.userId !== user.id || cookie.credentials?.userId !== user.id ||
      api.credentials?.role !== user.role || cookie.credentials?.role !== user.role ||
      api.artifacts?.ucrmSessionId !== pair.ucrmSessionId || cookie.artifacts?.token !== pair.token ||
      api.artifacts?.tokenId !== cookie.artifacts?.tokenId) fail('ADMISSION_DENIED');
    return tokenMetadata(api);
  }
  async function fullResult(body, user, pair, publishSuccess) {
    try {
      const metadata = await checkedPair(pair, user, body.audit);
      const fresh = await eligible(user.id);
      configured(body, await state());
      if (fresh.role !== user.role || fresh.ucrmRole !== user.ucrmRole || fresh.totpAuthEnabled !== user.totpAuthEnabled) fail('ADMISSION_DENIED');
      if (publishSuccess) {
        await bruteForce.userLoginSuccess(user.username, body.audit.remoteAddress);
        await messageHub.publish(messages.userLoginSuccess({ ...body.audit, userId: user.id }));
      }
      return { kind: 'session', token: pair.token, ucrmSessionId: pair.ucrmSessionId,
        cookieTtlMs: user.keepMeSignedIn ? user.sessionTimeout : null,
        user: projection(user), createdAt: seconds(metadata.createdAt), receipt: receipts.issue(user.id, 'session', pair.ucrmSessionId) };
    } catch (error) {
      await auth.removeTokenBySessionId(pair.ucrmSessionId);
      throw error;
    }
  }
  function prune() { for (const [id, value] of attempts) if (value.until <= now() && !value.busy) attempts.delete(id); }
  function reserve(body) {
    const time = Math.floor(now() / 1000);
    if (body.assertedAt > time + 30 || body.expiresAt <= time || body.assertedAt < time - 60) fail('ASSERTION_EXPIRED');
    prune();
    if (attempts.has(body.transactionId)) fail('TRANSACTION_USED');
    if (attempts.size >= attemptLimit) fail('BUSY');
    const attempt = { nativeUserId: body.nativeUserId, until: (body.expiresAt + 31) * 1000, busy: true, kind: 'issuing' };
    attempts.set(body.transactionId, attempt);
    return attempt;
  }
  async function issue(body) {
    const attempt = reserve(body);
    let user;
    try {
      user = await eligible(body.nativeUserId);
      await bruteForce.addAttemptForLogin(user.username, body.audit.remoteAddress);
      user = await eligible(body.nativeUserId);
      configured(body, await state());
      // The authenticated RP has already validated the OIDC identity. The
      // provider owns authentication/MFA for this path. Issue through the
      // native factory without changing the account's local TOTP settings;
      // native password routes continue to enforce those settings themselves.
      const pair = await auth.createSessionToken({ cmUser: user, data: { ucrmOidc: { v: 2, transactionId: body.transactionId } } });
      attempt.kind = 'consumed';
      return await fullResult(body, user, pair, true);
    } catch (error) {
      attempt.kind = 'failed';
      if (user) await messageHub.publish(messages.userLoginFailed({ ...body.audit, username: user.username }));
      throw nativeError(error);
    } finally { attempt.busy = false; }
  }
  async function completeMfa(body) {
    // An adapter upgrade already invalidates in-memory MFA attempts. Never
    // promote a legacy challenge into a session under the new OIDC policy.
    // Keep protocol-2 receipt verification and revoke support for safe cleanup.
    receipts.verify(body.receipt, body.nativeUserId, 'mfa', body.twoFactorToken);
    fail('MFA_EXPIRED');
  }
  return async function handle(body) {
    parse(body);
    const row = await pluginRow();
    if (body.operation === 'status') {
      const value = await state(row);
      return { kind: 'status', protocol: 2, enabled: value.enabled, pluginEnabled: value.pluginEnabled,
        serverEpoch: epoch, configRevision: value.revision, nativeVersion: profile.version, sourceBundleSha256: profile.sourceHash };
    }
    epochCheck(body);
    if (body.operation === 'revoke') {
      receipts.verify(body.receipt, body.nativeUserId, body.kind, body.artifact);
      if (body.kind === 'session') await auth.removeTokenBySessionId(body.artifact); else await auth.removeToken(body.artifact);
      return { kind: 'revoked' };
    }
    if (body.operation === 'describe-caller') {
      const valid = await auth.validateSessionId(body.callerSessionId, body.audit.remoteAddress);
      const metadata = await tokenMetadata(valid);
      // Recognize an existing different native identity even when it could not
      // newly enter through OIDC. PHP applies CRM management authorization.
      const user = await users.getUser(valid.credentials.userId).toPromise();
      if (!user || user.id !== valid.credentials.userId || user.enabled !== true ||
        typeof user.username !== 'string' || !NATIVE_ROLES.has(user.role)) fail('ADMISSION_DENIED');
      return { kind: 'caller', nativeUserId: user.id, username: user.username, role: user.role, ucrmRole: user.ucrmRole ?? null,
        createdAt: seconds(metadata.createdAt), source: valid.artifacts?.data?.ucrmOidc?.v === 2 ? 'adapter' : 'native-unattributed',
        sessionId: body.callerSessionId };
    }
    configured(body, await state(row));
    if (body.operation === 'resolve') {
      const matches = await dal.userRepository.findByEmail(body.email);
      if (!Array.isArray(matches) || matches.length !== 1) fail('ADMISSION_DENIED');
      return { kind: 'user', user: projection(await eligible(matches[0].id)) };
    }
    if (body.operation === 'inspect') return { kind: 'user', user: projection(await eligible(body.nativeUserId)) };
    if (body.operation === 'issue') return issue(body);
    return completeMfa(body);
  };
}
module.exports = { PLUGIN_NAME, PLUGIN_SQL, SCHEMAS, UUID, createNativeHandler };
