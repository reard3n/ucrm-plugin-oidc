'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const net = require('node:net');
const path = require('node:path');
const cluster = require('node:cluster');
const { createProtocol, derive, MAX_FRAME_BYTES } = require('./protocol.cjs');
const { createNativeHandler } = require('./native.cjs');
const SOCKET_PATH = '/run/ucrm-oidc-adapter/native-session.sock';
const KEY_PATH = '/run/secrets/ucrm-oidc-key';
const CONFIG_PATH = '/opt/ucrm-oidc-adapter/config.json';
const PLUGIN_CONFIG_PATH = '/opt/ucrm-oidc-crm-data/ucrm/data/plugins/ucrm-oidc/data/config.json';
const PROFILES = Object.freeze({
  'uisp-2.4.220': Object.freeze({ version: '2.4.220', bundlePath: '/home/app/unms/index.js', legacyTotpSecretFlag: true,
    sourceHash: '162a5b9546661210827c3f49469e6cf88298007dd64b90d7fe0cd425be10f436' }),
  'uisp-3.1.73': Object.freeze({ version: '3.1.73', bundlePath: '/home/app/unms/api.js', legacyTotpSecretFlag: false,
    sourceHash: '337b075359c7997e3401043c13ca3372da6827e9b8ba9e642b8baa7ba578ec41' })
});

async function readRegular(file, maximum, secret = false) {
  const handle = await fs.promises.open(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
  try {
    const stat = await handle.stat();
    if (!stat.isFile() || stat.size < 1 || stat.size > maximum ||
      (secret && ((stat.mode & 0o077) !== 0 || stat.uid !== process.getuid()))) throw new Error('Invalid adapter file');
    const bytes = await handle.readFile();
    if (bytes.length > maximum) throw new Error('Oversized adapter file');
    return bytes;
  } finally { await handle.close(); }
}
async function removeStaleSocket(socketPath) {
  let stat;
  try { stat = await fs.promises.lstat(socketPath); } catch (error) { if (error.code === 'ENOENT') return; throw error; }
  if (!stat.isSocket() || stat.uid !== process.getuid()) throw new Error('Unexpected socket path');
  const live = await new Promise((resolve, reject) => {
    const probe = net.createConnection(socketPath);
    probe.once('connect', () => { probe.destroy(); resolve(true); });
    probe.once('error', error => {
      probe.destroy();
      if (['ECONNREFUSED', 'ENOENT'].includes(error.code)) resolve(false); else reject(error);
    });
    probe.setTimeout(500, () => { probe.destroy(); reject(new Error('Socket probe timeout')); });
  });
  if (live) throw new Error('Adapter already active');
  const current = await fs.promises.lstat(socketPath);
  if (!current.isSocket() || current.ino !== stat.ino || current.uid !== stat.uid) throw new Error('Socket ownership changed');
  await fs.promises.unlink(socketPath);
}
async function listen(dispatch, discard) {
  const parent = await fs.promises.lstat(path.dirname(SOCKET_PATH));
  if (!parent.isDirectory() || parent.isSymbolicLink() || parent.uid !== process.getuid() || (parent.mode & 0o077) !== 0) throw new Error('Unsafe socket parent');
  await removeStaleSocket(SOCKET_PATH);
  let active = 0;
  const connections = new Set();
  const listener = net.createServer(socket => {
    if (active >= 16) { socket.destroy(); return; }
    active += 1;
    connections.add(socket);
    socket.once('close', () => { active -= 1; connections.delete(socket); });
    socket.on('error', () => {});
    socket.setTimeout(5000, () => socket.destroy());
    let buffered = Buffer.alloc(0), handled = false;
    socket.on('data', async chunk => {
      try {
        if (handled || buffered.length + chunk.length > MAX_FRAME_BYTES + 1) { socket.destroy(); return; }
        buffered = Buffer.concat([buffered, chunk]);
        const newline = buffered.indexOf(10);
        if (newline < 0) return;
        handled = true;
        if (newline !== buffered.length - 1) { socket.destroy(); return; }
        const response = await dispatch(buffered.subarray(0, newline));
        if (socket.destroyed) { if (response.ok) await discard(response.result); return; }
        socket.end(JSON.stringify(response) + '\n');
      } catch { socket.destroy(); }
    });
  });
  let inode;
  async function close() {
    for (const connection of connections) connection.destroy();
    if (listener.listening) await new Promise(resolve => listener.close(resolve));
    try {
      const stat = await fs.promises.lstat(SOCKET_PATH);
      if (inode && stat.isSocket() && stat.ino === inode.ino && stat.uid === inode.uid) await fs.promises.unlink(SOCKET_PATH);
    } catch { /* Node may remove its own socket during close. */ }
  }
  try {
    await new Promise((resolve, reject) => { listener.once('error', reject); listener.listen(SOCKET_PATH, resolve); });
    inode = await fs.promises.lstat(SOCKET_PATH);
    listener.on('error', () => { void close(); console.error('UCRM OIDC adapter socket unavailable'); });
    await fs.promises.chmod(SOCKET_PATH, 0o600);
    listener.unref();
    return { close };
  } catch (error) { await close(); throw error; }
}
async function install(server, dependencies = {}) {
  const env = dependencies.env || process.env;
  if (env.UCRM_OIDC_ADAPTER_ENABLED !== '1' || cluster.isWorker) return { enabled: false, reason: 'DISABLED' };
  let listener;
  try {
    const read = dependencies.readRegular || readRegular;
    const config = JSON.parse((await read(CONFIG_PATH, 16384)).toString('utf8'));
    const profile = PROFILES[config.profile];
    if (!profile || config.protocol !== 2 || config.pluginName !== 'ucrm-oidc' ||
      config.pluginConfigPath !== PLUGIN_CONFIG_PATH || config.sourceBundleSha256 !== profile.sourceHash ||
      !/^[0-9a-f]{64}$/.test(config.runningBundleSha256 ?? '') ||
      !(config.canaryEmailDomain === null || config.canaryEmailDomain === 'oidc229.example.com')) throw new Error('Unknown adapter build');
    const bundle = await read(profile.bundlePath, 24 * 1024 * 1024);
    if (crypto.createHash('sha256').update(bundle).digest('hex') !== config.runningBundleSha256) throw new Error('Unknown native bundle');
    const keyText = (await read(KEY_PATH, 66, true)).toString('utf8');
    if (!/^[0-9a-f]{64}\r?\n?$/.test(keyText)) throw new Error('Invalid adapter key');
    const master = Buffer.from(keyText.trimEnd(), 'hex');
    const handler = createNativeHandler({ server, readConfig: () => read(PLUGIN_CONFIG_PATH, 65536),
      receiptKey: derive(master, 'adapter-receipt'), profile, nativeMessages: dependencies.nativeMessages,
      canaryEmailDomain: config.canaryEmailDomain });
    const dispatch = createProtocol({ key: derive(master, 'adapter-transport'), handler });
    master.fill(0);
    const discard = async result => {
      if (result.kind === 'session') await server.plugins.auth.removeTokenBySessionId(result.ucrmSessionId);
      if (result.kind === 'mfa') await server.plugins.auth.removeToken(result.twoFactorToken);
    };
    listener = await (dependencies.listen || listen)(dispatch, discard);
    server.events.once('stop', () => { void listener.close(); });
    return { enabled: true, close: listener.close };
  } catch {
    if (listener) await listener.close();
    console.error('UCRM OIDC adapter unavailable; native login remains active');
    return { enabled: false, reason: 'BOOTSTRAP_FAILED' };
  }
}
module.exports = { CONFIG_PATH, KEY_PATH, PLUGIN_CONFIG_PATH, PROFILES, SOCKET_PATH, install, listen, readRegular, removeStaleSocket };
