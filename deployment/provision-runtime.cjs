'use strict';

// One-time initialization of four NEW, dedicated resource directories. Existing
// native data, service accounts, groups and nonempty resources are never changed.
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const identity = require('../adapter/identity.cjs');
function initialize(root, policy) {
  if (process.getuid() !== 0) throw new Error('root_provisioner_required');
  identity.validate(policy); const access = identity.permissions(policy);
  const dirs = Object.fromEntries(['key', 'socket', 'state', 'identity'].map(name => [name, path.join(root, name)]));
  const base = fs.lstatSync(root);
  if (!base.isDirectory() || base.isSymbolicLink()) throw new Error('dedicated_resource_root_required');
  for (const directory of Object.values(dirs)) {
    const stat = fs.lstatSync(directory);
    if (!stat.isDirectory() || stat.isSymbolicLink() || fs.readdirSync(directory).length !== 0) {
      throw new Error('new_empty_resource_directories_required');
    }
  }
  const key = path.join(dirs.key, 'ucrm-oidc-key');
  fs.writeFileSync(key, crypto.randomBytes(32).toString('hex') + '\n', {flag: 'wx', mode: 0o400});
  const contract = path.join(dirs.identity, 'runtime-identity.json');
  fs.writeFileSync(contract, JSON.stringify(policy, null, 2) + '\n', {flag: 'wx', mode: 0o444});
  fs.chownSync(contract, 0, 0); fs.chmodSync(contract, 0o444);
  for (const [file, required] of [[key, access.key], [dirs.key, access.keyDirectory],
    [dirs.socket, access.socketDirectory], [dirs.state, access.stateDirectory]]) {
    fs.chownSync(file, required.uid, required.gid); fs.chmodSync(file, required.mode);
    if (!identity.matches(fs.lstatSync(file), required, file === key ? 'file' : 'directory')) throw new Error('resource_permission_verification_failed');
  }
  fs.chownSync(dirs.identity, 0, 0); fs.chmodSync(dirs.identity, 0o555);
  return {version: 1, runtimeIdentity: policy, permissions: access, generatedFreshInstallationKey: true,
    modifiedNativeAccounts: false, modifiedExistingData: false};
}
if (require.main === module) {
  try {
    if (process.argv.length !== 5 || process.argv[2] !== '--initialize') throw new Error('usage_initialize_identity_file_resource_root');
    const source = fs.lstatSync(process.argv[3]);
    if (!source.isFile() || source.isSymbolicLink() || source.size < 1 || source.size > 1024) throw new Error('invalid_identity_file');
    console.log(JSON.stringify(initialize(path.resolve(process.argv[4]), JSON.parse(fs.readFileSync(process.argv[3], 'utf8')))));
  } catch (error) { console.error(error.message); process.exitCode = 1; }
}
module.exports = {initialize};
