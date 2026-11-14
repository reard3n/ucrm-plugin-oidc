'use strict';

const crypto = require('node:crypto');
const MAX_FRAME_BYTES = 16384;
const MAX_BODY_BYTES = 8192;
const HEX = /^[0-9a-f]{64}$/;
class AdapterError extends Error { constructor(code) { super(code); this.code = code; } }
function fail(code) { throw new AdapterError(code); }
function object(value) { return value !== null && typeof value === 'object' && !Array.isArray(value); }
function exactKeys(value, keys) { return object(value) && Object.keys(value).sort().join('|') === [...keys].sort().join('|'); }
function derive(master, purpose) {
  if (!Buffer.isBuffer(master) || master.length !== 32) throw new Error('Invalid key');
  return Buffer.from(crypto.hkdfSync('sha256', master, Buffer.alloc(0), 'ucrm-oidc:' + purpose + ':v2', 32));
}
function signingInput(value) {
  return ['UCRM-OIDC-ADAPTER-V2', value.caller, value.keyId, String(value.at), value.nonce, value.body].join('\n');
}
function sign(value, key) { return crypto.createHmac('sha256', key).update(signingInput(value)).digest('hex'); }
function createProtocol({ key, handler, now = Date.now, nonceLimit = 4096 }) {
  const used = new Map();
  return async function dispatch(frame) {
    try {
      if (!Buffer.isBuffer(frame) || frame.length < 1 || frame.length > MAX_FRAME_BYTES) fail('BAD_REQUEST');
      let value;
      try { value = JSON.parse(frame.toString('utf8')); } catch { fail('BAD_REQUEST'); }
      if (!exactKeys(value, ['v', 'caller', 'keyId', 'at', 'nonce', 'body', 'mac']) || value.v !== 2 ||
          value.caller !== 'ucrm-oidc' || value.keyId !== 'installation-v1' || !Number.isSafeInteger(value.at) ||
          typeof value.nonce !== 'string' || !HEX.test(value.nonce) || typeof value.mac !== 'string' || !HEX.test(value.mac) ||
          typeof value.body !== 'string' || !/^[A-Za-z0-9_-]+$/.test(value.body)) fail('AUTHENTICATION_FAILED');
      if (!crypto.timingSafeEqual(Buffer.from(sign(value, key), 'hex'), Buffer.from(value.mac, 'hex'))) fail('AUTHENTICATION_FAILED');
      const time = now();
      if (Math.abs(Math.floor(time / 1000) - value.at) > 30) fail('STALE_REQUEST');
      for (const [nonce, until] of used) if (until <= time) used.delete(nonce);
      if (used.has(value.nonce)) fail('REPLAY');
      if (used.size >= nonceLimit) fail('BUSY');
      used.set(value.nonce, time + 65000);
      const body = Buffer.from(value.body, 'base64url');
      if (body.length > MAX_BODY_BYTES || body.toString('base64url') !== value.body) fail('BAD_REQUEST');
      let parsed;
      try { parsed = JSON.parse(body.toString('utf8')); } catch { fail('BAD_REQUEST'); }
      if (!object(parsed)) fail('BAD_REQUEST');
      return { ok: true, result: await handler(parsed) };
    } catch (error) {
      return { ok: false, error: { code: error instanceof AdapterError ? error.code : 'NATIVE_UNAVAILABLE' } };
    }
  };
}
function createReceipts(key) {
  function signature(payload) { return crypto.createHmac('sha256', key).update('UCRM-OIDC-OWNED-ARTIFACT-V2\n' + payload).digest('hex'); }
  function issue(nativeUserId, kind, artifact) {
    const payload = Buffer.from(JSON.stringify({ v: 2, nativeUserId, kind,
      artifactHash: crypto.createHash('sha256').update(artifact).digest('hex') })).toString('base64url');
    return payload + '.' + signature(payload);
  }
  function verify(receipt, nativeUserId, kind, artifact) {
    if (typeof receipt !== 'string' || receipt.length > 1024) fail('RECEIPT_INVALID');
    const [payload, mac, extra] = receipt.split('.');
    if (extra !== undefined || !payload || !/^[A-Za-z0-9_-]+$/.test(payload) || !HEX.test(mac ?? '')) fail('RECEIPT_INVALID');
    if (!crypto.timingSafeEqual(Buffer.from(signature(payload), 'hex'), Buffer.from(mac, 'hex'))) fail('RECEIPT_INVALID');
    let value;
    try { value = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8')); } catch { fail('RECEIPT_INVALID'); }
    if (!exactKeys(value, ['v', 'nativeUserId', 'kind', 'artifactHash']) || value.v !== 2 ||
        value.nativeUserId !== nativeUserId || value.kind !== kind ||
        value.artifactHash !== crypto.createHash('sha256').update(artifact).digest('hex')) fail('RECEIPT_INVALID');
  }
  return { issue, verify };
}
module.exports = { AdapterError, MAX_FRAME_BYTES, MAX_BODY_BYTES, HEX, createProtocol, createReceipts, derive, exactKeys, fail, object, sign, signingInput };
