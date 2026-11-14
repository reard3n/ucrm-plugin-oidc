'use strict';

// Deployment identity is discovered from the existing native processes. It is
// operator configuration, never an image-build UID or an OIDC provider claim.
const fs = require('node:fs');
const PATH = '/etc/ucrm-oidc/runtime-identity.json';
function keys(value, expected) {
  return value && typeof value === 'object' && !Array.isArray(value)
    && Object.keys(value).sort().join(',') === [...expected].sort().join(',');
}
function validate(value) {
  if (!keys(value, ['version', 'api', 'crm']) || value.version !== 1) throw new Error('invalid_runtime_identity');
  for (const name of ['api', 'crm']) {
    if (!keys(value[name], ['uid', 'gid']) || !['uid', 'gid'].every(key =>
      Number.isSafeInteger(value[name][key]) && value[name][key] > 0 && value[name][key] <= 2147483647)) {
      throw new Error('invalid_runtime_identity');
    }
  }
  return value;
}
function permissions(value) {
  validate(value);
  const sharedUser = value.api.uid === value.crm.uid;
  const group = sharedUser ? value.api.gid : value.crm.gid;
  return {
    key: {uid: value.api.uid, gid: group, mode: sharedUser ? 0o400 : 0o440},
    keyDirectory: {uid: value.api.uid, gid: group, mode: sharedUser ? 0o500 : 0o510},
    // setgid makes newly bound sockets inherit the CRM group even when the
    // native API has a different primary group. CRM cannot replace the socket.
    socketDirectory: {uid: value.api.uid, gid: group, mode: sharedUser ? 0o700 : 0o2710},
    socket: {uid: value.api.uid, gid: group, mode: sharedUser ? 0o600 : 0o660},
    stateDirectory: {uid: value.crm.uid, gid: value.crm.gid, mode: 0o700},
  };
}
function matches(stat, expected, kind) {
  return !stat.isSymbolicLink() && (kind === 'directory' ? stat.isDirectory() : kind === 'socket' ? stat.isSocket() : stat.isFile())
    && stat.uid === expected.uid && stat.gid === expected.gid && (stat.mode & 0o7777) === expected.mode;
}
function read(file = PATH) {
  const fd = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
  try {
    const stat = fs.fstatSync(fd);
    if (!stat.isFile() || stat.uid !== 0 || (stat.mode & 0o222) !== 0 || stat.size < 1 || stat.size > 1024) {
      throw new Error('unsafe_runtime_identity');
    }
    return validate(JSON.parse(fs.readFileSync(fd, 'utf8')));
  } finally { fs.closeSync(fd); }
}
function assertProcess(value, uid = process.getuid(), gid = process.getgid()) {
  validate(value);
  if (uid !== value.api.uid || gid !== value.api.gid) throw new Error('native_process_identity_changed');
}
module.exports = {PATH, validate, permissions, matches, read, assertProcess};
