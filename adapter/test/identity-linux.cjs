'use strict';
// Run only in an isolated Linux container with disposable /run and policy tmpfs.
// Real UID/GID transitions and Unix permissions; no native service or database.
const fs = require('node:fs');
const net = require('node:net');
const crypto = require('node:crypto');
const assert = require('node:assert/strict');
const {spawn, spawnSync} = require('node:child_process');
const identity = require('../identity.cjs');
const {listen, readRegular, KEY_PATH, SOCKET_PATH} = require('../index.cjs');
const {createProtocol, derive, sign} = require('../protocol.cjs');
const {initialize} = require('../../deployment/provision-runtime.cjs');
const mode = process.argv[2];
async function exchange(frame) {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection(SOCKET_PATH); let bytes = '';
    socket.setTimeout(1500, () => socket.destroy(new Error('timeout')));
    socket.once('connect', () => socket.end(JSON.stringify(frame) + '\n'));
    socket.on('data', value => { bytes += value.toString(); });
    socket.once('error', reject); socket.once('end', () => { try { resolve(JSON.parse(bytes)); } catch (e) { reject(e); } });
  });
}
async function child() {
  if (mode === 'server') {
    identity.assertProcess(identity.read());
    const master = Buffer.from((await readRegular(KEY_PATH, 66, true)).toString().trim(), 'hex');
    const server = await listen(createProtocol({key: derive(master, 'adapter-transport'), handler: async body => ({operation: body.operation})}), async () => {});
    process.send({ready: true});
    process.once('message', async () => { await server.close(); process.exit(0); });
  } else if (mode === 'client') {
    const master = Buffer.from(fs.readFileSync(KEY_PATH, 'utf8').trim(), 'hex');
    const frame = {v: 2, caller: 'ucrm-oidc', keyId: 'installation-v1', at: Math.floor(Date.now()/1000),
      nonce: crypto.randomBytes(32).toString('hex'), body: Buffer.from('{"operation":"status"}').toString('base64url')};
    frame.mac = sign(frame, derive(master, 'adapter-transport'));
    assert.deepEqual(await exchange(frame), {ok: true, result: {operation: 'status'}});
    frame.nonce = crypto.randomBytes(32).toString('hex'); frame.mac = '0'.repeat(64);
    assert.equal((await exchange(frame)).error.code, 'AUTHENTICATION_FAILED');
    if (process.getuid() !== identity.read().api.uid) {
      assert.throws(() => fs.unlinkSync(SOCKET_PATH), error => ['EACCES', 'EPERM'].includes(error.code));
      assert.throws(() => fs.writeFileSync(KEY_PATH, 'changed'), error => ['EACCES', 'EPERM'].includes(error.code));
    }
  } else if (mode === 'outsider') {
    assert.throws(() => fs.readFileSync(KEY_PATH), error => error.code === 'EACCES');
    await assert.rejects(exchange({}), error => error.code === 'EACCES');
  }
}
async function parent() {
  assert.equal(process.platform, 'linux'); assert.equal(process.getuid(), 0);
  assert.equal(process.env.UCRM_OIDC_ISOLATED_IDENTITY_TEST, '1');
  assert.equal(fs.existsSync(KEY_PATH), false); assert.equal(fs.existsSync(SOCKET_PATH), false);
  const cases = [
    {api: {uid: 1001, gid: 1001}, crm: {uid: 1000, gid: 1000}},
    {api: {uid: 17321, gid: 17322}, crm: {uid: 24981, gid: 24982}},
    {api: {uid: 24981, gid: 24982}, crm: {uid: 17321, gid: 17322}},
    {api: {uid: 4137, gid: 4138}, crm: {uid: 4137, gid: 4139}},
  ];
  const reports = [];
  for (const value of cases) {
    const policy = {version: 1, ...value}; const p = identity.permissions(policy);
    const resourceRoot = '/run/provision'; fs.mkdirSync(resourceRoot);
    for (const name of ['key', 'socket', 'state', 'identity']) fs.mkdirSync(resourceRoot + '/' + name);
    const provisioned = initialize(resourceRoot, policy); assert.deepEqual(provisioned.runtimeIdentity, policy);
    assert.deepEqual(identity.read(resourceRoot + '/identity/runtime-identity.json'), policy);
    const retainedKey = fs.readFileSync(resourceRoot + '/key/ucrm-oidc-key');
    assert.throws(() => initialize(resourceRoot, policy), /new_empty_resource_directories_required/);
    assert.deepEqual(fs.readFileSync(resourceRoot + '/key/ucrm-oidc-key'), retainedKey);
    fs.rmSync(resourceRoot, {recursive: true});
    fs.mkdirSync('/run/secrets'); fs.mkdirSync('/run/ucrm-oidc-adapter');
    fs.writeFileSync(KEY_PATH, crypto.randomBytes(32).toString('hex') + '\n', {mode: 0o400});
    for (const [file, access] of [[KEY_PATH, p.key], ['/run/secrets', p.keyDirectory], ['/run/ucrm-oidc-adapter', p.socketDirectory]]) {
      fs.chownSync(file, access.uid, access.gid); fs.chmodSync(file, access.mode);
    }
    fs.writeFileSync(identity.PATH, JSON.stringify(policy), {mode: 0o444}); fs.chmodSync(identity.PATH, 0o444);
    // Recreate the actual Unix socket twice; the CRM group must survive restart.
    for (let generation = 0; generation < 2; generation++) {
      const server = spawn(process.execPath, [__filename, 'server'], {uid: value.api.uid, gid: value.api.gid, stdio: ['ignore', 'pipe', 'pipe', 'ipc']});
      let error = ''; server.stderr.on('data', bytes => { error += bytes; });
      const exited = new Promise(resolve => server.once('exit', (code, signal) => resolve({code, signal})));
      try {
        await Promise.race([new Promise(resolve => server.once('message', resolve)), exited.then(() => { throw new Error('Server refused test identity: ' + error); }),
          new Promise((_, reject) => setTimeout(() => reject(new Error('server timeout')), 5000).unref())]);
        assert(identity.matches(fs.lstatSync(SOCKET_PATH), p.socket, 'socket'));
        for (const [role, ids] of [['client', value.crm], ['outsider', {uid: 29001, gid: 29002}]]) {
          const child = spawn(process.execPath, [__filename, role], {uid: ids.uid, gid: ids.gid, stdio: ['ignore', 'pipe', 'pipe']});
          let diagnostic = ''; child.stderr.on('data', bytes => { diagnostic += bytes; });
          const status = await new Promise(resolve => child.once('exit', (code, signal) => resolve({code, signal})));
          assert.deepEqual(status, {code: 0, signal: null}, role + ' permission check failed: ' + diagnostic);
        }
        server.send('close'); assert.deepEqual(await exited, {code: 0, signal: null}, error);
        assert.equal(fs.existsSync(SOCKET_PATH), false);
      } finally { if (server.exitCode === null) { server.kill('SIGTERM'); await exited; } }
    }
    reports.push({api: value.api, crm: value.crm, authenticatedTransportPassed: true, wrongMacDenied: true,
      unrelatedUidDenied: true, clientCannotReplaceSocketOrKey: value.api.uid !== value.crm.uid, socketRestartPassed: true,
      freshProvisioningPassed: true, nonemptyResourcesRefusedWithoutChangingKey: true});
    fs.unlinkSync(KEY_PATH); fs.rmdirSync('/run/secrets'); fs.rmdirSync('/run/ucrm-oidc-adapter'); fs.unlinkSync(identity.PATH);
  }
  console.log(JSON.stringify({complete: true, cases: reports, nativeServicesTouched: false}));
}
(mode ? child() : parent()).catch(error => { console.error(error.message); process.exitCode = 1; });
