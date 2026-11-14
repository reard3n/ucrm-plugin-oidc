'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const identity = require('../identity.cjs');
test('service identities come from deployment values, including unequal arbitrary IDs', () => {
  for (const [api, crm] of [[17321, 24981], [24981, 17321], [1001, 1000], [4137, 4137]]) {
    const policy = {version: 1, api: {uid: api, gid: api + 10}, crm: {uid: crm, gid: crm + 20}};
    const permissions = identity.permissions(policy);
    assert.equal(permissions.key.uid, api);
    assert.equal(permissions.stateDirectory.uid, crm);
    assert.equal(permissions.key.gid, api === crm ? api + 10 : crm + 20);
    assert.equal(permissions.key.mode & 0o007, 0);
    assert.equal(permissions.socketDirectory.mode & 0o027, 0);
    assert.equal(permissions.socket.mode & 0o007, 0);
    assert.doesNotThrow(() => identity.assertProcess(policy, api, api + 10));
    assert.throws(() => identity.assertProcess(policy, api + 1, api + 10), /identity_changed/);
    assert.throws(() => identity.assertProcess(policy, api, api + 11), /identity_changed/);
  }
});
test('ambiguous, root, malformed and extra identity fields are refused', () => {
  const valid = {version: 1, api: {uid: 3021, gid: 4021}, crm: {uid: 5021, gid: 6021}};
  for (const value of [null, [], {}, {...valid, version: 2}, {...valid, override: true}]) assert.throws(() => identity.validate(value));
  for (const field of ['uid', 'gid']) for (const bad of [0, -1, 1.5, '1001', null, 2147483648]) {
    for (const service of ['api', 'crm']) assert.throws(() => identity.validate({...valid, [service]: {...valid[service], [field]: bad}}));
  }
});
test('split identities have a non-writable client directory and setgid socket inheritance', () => {
  const p = identity.permissions({version: 1, api: {uid: 2201, gid: 2202}, crm: {uid: 3301, gid: 3302}});
  assert.deepEqual(p.socketDirectory, {uid: 2201, gid: 3302, mode: 0o2710});
  assert.equal(p.socket.mode, 0o660);
  assert.equal(p.key.mode, 0o440);
  assert.equal(p.keyDirectory.mode, 0o510);
});
