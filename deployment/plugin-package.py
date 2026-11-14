"""Export committed plugin source, then assemble a locked dependency native ZIP."""
from __future__ import annotations
import argparse
import datetime
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import tarfile
import zipfile

PREFIX = 'plugin'
COMPOSER_SHA = 'dd158c0afd41d15fac89e1b4e47b5d42911fe316c3687cd5edac98319b25d028'
PHP_IMAGE = 'ubnt/unms-crm@sha256:23f9284acd80faf4d7f0afff871c5a2f1d1b2c492280a8fc1670679f0e3b3724'
ROOT_FILES = {'manifest.json', 'composer.json', 'composer.lock', 'main.php', 'public.php', 'README.md',
              'LICENSE', 'LICENSE.md', 'NOTICE', 'NOTICE.md',
              *('hook_' + name + '.php' for name in ['install', 'configure', 'enable', 'disable', 'update', 'remove'])}
REQUIRED = {'manifest.json', 'composer.json', 'composer.lock', 'LICENSE', 'NOTICE.md', 'main.php', 'public.php', 'public/login-button.js',
            *('hook_' + name + '.php' for name in ['install', 'configure', 'enable', 'disable', 'update', 'remove'])}
VENDOR_EXCLUDED = {'tests', 'test', 'spec', 'specs', 'fixtures', 'examples', 'docs', '.git', '.github', 'bin'}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def safe_path(name):
    path = PurePosixPath(name)
    if not name or path.is_absolute() or '\\' in name or any(p in ['', '.', '..'] for p in name.split('/')):
        raise ValueError('Unsafe package path')
    if any(ord(c) < 32 or ord(c) == 127 for c in name) or ':' in name or any(p.endswith(('.', ' ')) for p in path.parts):
        raise ValueError('Unsafe package path')
    return path


def source_allowed(name):
    parts = safe_path(name).parts
    if any(p.lower() in {'data', 'private', 'vendor', 'tests', 'test', '.git', '.env'} for p in parts):
        return False
    if name in ROOT_FILES:
        return True
    return len(parts) > 1 and parts[0] in {'src', 'public'} and Path(name).suffix.lower() in {
        '.php', '.js', '.css', '.json', '.svg', '.png', '.jpg', '.webp', '.ico', '.woff', '.woff2'}


def package_set(lock):
    packages = lock.get('packages')
    if not isinstance(packages, list) or not packages:
        raise ValueError('Production dependency lock required')
    result = {}
    for package in packages:
        name = package.get('name', '')
        if not re.fullmatch(r'[a-z0-9_.-]+/[a-z0-9_.-]+', name) or name in result:
            raise ValueError('Invalid locked package identity')
        result[name] = package
    return result


def validate_installed(lock, installed):
    expected = package_set(lock)
    packages = installed.get('packages') if isinstance(installed, dict) else installed
    if not isinstance(packages, list) or len(packages) != len(expected):
        raise ValueError('Installed dependency set differs from production lock')
    seen = set()
    for package in packages:
        name = package.get('name')
        if name not in expected or name in seen or package.get('dev_requirement'):
            raise ValueError('Unexpected or development dependency')
        seen.add(name)
        for field in ['version', 'type']:
            if package.get(field) != expected[name].get(field):
                raise ValueError('Installed dependency metadata differs from lock')
        for field in ['source', 'dist']:
            if package.get(field, {}).get('reference') != expected[name].get(field, {}).get('reference'):
                raise ValueError('Installed dependency reference differs from lock')
        if package.get('dist', {}).get('type') == 'path':
            raise ValueError('Local path dependencies are not release artifacts')
    return sorted(seen)


def retain_vendor_path(name, runtime_autoload):
    # Some maintained libraries publish reusable classes under a Test namespace.
    # Composer's production autoloader, not a directory's spelling, decides
    # whether those PHP files are part of the installed runtime interface.
    parts = safe_path(name).parts
    return name in runtime_autoload or not any(part.lower() in VENDOR_EXCLUDED for part in parts[1:])


def commit_zip_time(epoch):
    if not isinstance(epoch, int):
        raise ValueError('Integer source commit timestamp required')
    value = datetime.datetime.fromtimestamp(epoch, datetime.timezone.utc)
    if not 1980 <= value.year <= 2107:
        raise ValueError('Source commit timestamp outside ZIP range')
    return (value.year, value.month, value.day, value.hour, value.minute, value.second // 2 * 2)


def zip_bytes(entries, timestamp):
    seen = set()
    output = io.BytesIO()
    if sum(map(len, entries.values())) > 64 * 1024 * 1024 or len(entries) > 5000:
        raise ValueError('Unexpected package size')
    with zipfile.ZipFile(output, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name, data in sorted(entries.items()):
            safe_path(name)
            if name.casefold() in seen:
                raise ValueError('Duplicate case-insensitive package path')
            seen.add(name.casefold())
            member = zipfile.ZipInfo(name, date_time=timestamp)
            member.create_system = 3
            member.external_attr = (stat.S_IFREG | 0o644) << 16
            member.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(member, data, compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
    return output.getvalue()


def docker_context(value):
    if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9_.-]{1,64}', value):
        raise ValueError('Invalid Docker context name')
    return value


def local_docker_endpoint(value):
    return isinstance(value, str) and (value.startswith('unix:///') or value.startswith('npipe:////./pipe/'))


def composer_commands(root, context='default'):
    plugin = root / 'plugin'; tools = root / 'tools'
    container = ['docker', '--context', docker_context(context), 'run', '--rm', '--pull', 'never', '--platform', 'linux/amd64',
                 '--label', 'ucrm-oidc.purpose=isolated-package-build',
                 '--network', 'bridge', '--read-only', '--user', '1000:1000', '--cap-drop', 'ALL',
                 '--security-opt', 'no-new-privileges', '--memory', '768m', '--memory-swap', '768m',
                 '--cpus', '1', '--pids-limit', '128', '--tmpfs', '/tmp:rw,nosuid,nodev,size=268435456',
                 '--env', 'HOME=/tmp/composer', '--env', 'COMPOSER_HOME=/tmp/composer',
                 '--env', 'COMPOSER_CACHE_DIR=/tmp/composer-cache', '--env', 'COMPOSER_AUTH={}',
                 '--env', 'HTTP_PROXY=', '--env', 'HTTPS_PROXY=', '--env', 'ALL_PROXY=', '--env', 'NO_PROXY=',
                 '--mount', 'type=bind,source=' + str(plugin) + ',target=/work/plugin',
                 '--mount', 'type=bind,source=' + str(tools / 'composer.phar') + ',target=/tools/composer.phar,readonly',
                 '--workdir', '/work/plugin', '--entrypoint', 'php', PHP_IMAGE, '/tools/composer.phar']
    return {'validate': [*container, 'validate', '--strict', '--no-check-publish', '--no-check-all', '--check-lock'],
            'install': [*container, 'install', '--no-dev', '--no-scripts', '--no-plugins', '--prefer-dist',
                        '--classmap-authoritative', '--no-interaction', '--no-progress'],
            'audit': [*container, 'audit', '--locked', '--no-dev', '--no-interaction', '--format=json']}


def verify_source(root, receipt):
    if receipt.get('schemaVersion') != 1 or receipt.get('composerSha256') != COMPOSER_SHA or receipt.get('builderImage') != PHP_IMAGE:
        raise ValueError('Unrecognized source/dependency build contract')
    if digest((root / 'tools/composer.phar').read_bytes()) != COMPOSER_SHA:
        raise ValueError('Composer executable changed after preparation')
    entries = {}
    for name, expected in receipt['sourceFiles'].items():
        if not source_allowed(name):
            raise ValueError('Unapproved source path')
        file = root / 'plugin' / name
        if any(parent.is_symlink() for parent in [file, *file.parents] if parent != root.parent) or not file.is_file():
            raise ValueError('Missing or linked source file')
        data = file.read_bytes()
        if digest(data) != expected:
            raise ValueError('Committed plugin source changed during dependency install')
        entries[name] = data
    if digest(entries['composer.lock']) != receipt['lockSha256']:
        raise ValueError('Dependency lock changed')
    return entries


def prepare(args):
    repo = Path(__file__).resolve().parents[1]
    revision = subprocess.check_output(['git', '-C', str(repo), 'rev-parse', '--verify', args.revision + '^{commit}'], text=True).strip()
    source_epoch = int(subprocess.check_output(['git', '-C', str(repo), 'show', '-s', '--format=%ct', revision], text=True).strip())
    archive = subprocess.check_output(['git', '-C', str(repo), 'archive', '--format=tar', revision, '--', PREFIX])
    files = {}; seen = set()
    with tarfile.open(fileobj=io.BytesIO(archive), mode='r:') as contents:
        for member in contents:
            if member.isdir():
                continue
            path = safe_path(member.name)
            if not member.isfile() or not str(path).startswith(PREFIX + '/'):
                raise ValueError('Only regular committed plugin files may be packaged')
            name = str(path)[len(PREFIX) + 1:]
            if name.casefold() in seen:
                raise ValueError('Duplicate case-insensitive source path')
            seen.add(name.casefold())
            if not source_allowed(name) or member.size > 8 * 1024 * 1024:
                raise ValueError('Unapproved source path or oversized file: ' + name)
            files[name] = contents.extractfile(member).read()
    if not REQUIRED.issubset(files):
        raise ValueError('Commit lacks complete plugin entrypoints, hooks, lock or login asset')
    manifest = json.loads(files['manifest.json'])
    if manifest.get('information', {}).get('name') != 'ucrm-oidc':
        raise ValueError('Wrong native plugin identity')
    package_set(json.loads(files['composer.lock']))
    phar = args.composer.resolve(strict=True).read_bytes()
    if digest(phar) != COMPOSER_SHA:
        raise ValueError('Composer executable differs from qualified artifact')
    root = args.output.resolve()
    root.mkdir(parents=True, exist_ok=False)
    (root / 'source.tar').write_bytes(archive)
    plugin = root / 'plugin'; plugin.mkdir()
    tools = root / 'tools'; tools.mkdir()
    (tools / 'composer.phar').write_bytes(phar)
    for name, data in files.items():
        target = plugin / name; target.parent.mkdir(parents=True, exist_ok=True); target.write_bytes(data)
    receipt = {'schemaVersion': 1, 'revision': revision, 'archiveSha256': digest(archive),
               'sourceCommitEpoch': source_epoch, 'zipTimestampUtc': commit_zip_time(source_epoch),
               'sourceFiles': {name: digest(data) for name, data in sorted(files.items())},
               'composerSha256': COMPOSER_SHA, 'lockSha256': digest(files['composer.lock']), 'builderImage': PHP_IMAGE,
               'dockerContext': docker_context(args.docker_context), 'commands': composer_commands(root, args.docker_context),
               'commandsExecuted': False, 'runtimeSecretsIncluded': False}
    (root / 'source-receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    print(json.dumps({'prepared': True, 'revision': revision, 'buildRoot': str(root), 'dependencyCommandsExecuted': False}))


def dependencies(args):
    root = args.build.resolve(strict=True)
    receipt = json.loads((root / 'source-receipt.json').read_text())
    verify_source(root, receipt)
    context_name = docker_context(receipt['dockerContext'])
    commands = composer_commands(root, context_name)
    if commands != receipt['commands']:
        raise ValueError('Dependency command receipt changed')
    if (root / 'dependency-results.json').exists() or (root / 'plugin/vendor').exists():
        raise ValueError('Dependency build already attempted; retain evidence and use a fresh exact export')
    context = json.loads(subprocess.check_output(['docker', 'context', 'inspect', context_name]))[0]
    if not local_docker_endpoint(context['Endpoints']['docker']['Host']):
        raise ValueError('A local Unix socket or Windows named-pipe Docker endpoint is required')
    image = json.loads(subprocess.check_output(['docker', '--context', context_name, 'image', 'inspect', PHP_IMAGE]))[0]
    if image['Os'] != 'linux' or image['Architecture'] != 'amd64':
        raise ValueError('Unexpected PHP build platform')
    results = {'revision': receipt['revision'], 'builderImageId': image['Id'], 'composerSha256': COMPOSER_SHA,
               'lockSha256': receipt['lockSha256'], 'steps': {}, 'complete': False}
    for name in ['validate', 'install', 'audit']:
        result = subprocess.run(commands[name], capture_output=True)
        (root / ('composer-' + name + '.stdout')).write_bytes(result.stdout)
        (root / ('composer-' + name + '.stderr')).write_bytes(result.stderr)
        results['steps'][name] = {'exitCode': result.returncode, 'stdoutSha256': digest(result.stdout), 'stderrSha256': digest(result.stderr)}
        (root / 'dependency-results.json').write_text(json.dumps(results, indent=2) + '\n')
        print(json.dumps({'dependencyStep': name, 'exitCode': result.returncode}), flush=True)
        if result.returncode:
            raise SystemExit('Dependency qualification failed; inspect retained nonsecret build logs, do not update the lock')
        verify_source(root, receipt)
    code = r'''$loader=require '/work/plugin/vendor/autoload.php';$files=array_values($loader->getClassMap());
$extra='/work/plugin/vendor/composer/autoload_files.php';if(is_file($extra))$files=array_merge($files,array_values(require $extra));
$out=[];foreach($files as $file){$path=realpath($file);if(!$path||!str_starts_with($path,'/work/plugin/'))exit(4);$out[]=substr($path,13);}
$out=array_values(array_unique($out));sort($out);echo json_encode($out);'''
    command = commands['validate'][:commands['validate'].index(PHP_IMAGE) + 1] + ['-r', code]
    command[command.index('--network') + 1] = 'none'
    autoload = subprocess.run(command, capture_output=True)
    if autoload.returncode:
        raise SystemExit('Installed runtime autoloader inventory failed; retain build and do not package')
    inventory = json.loads(autoload.stdout)
    if not isinstance(inventory, list) or any(not isinstance(name, str) for name in inventory):
        raise ValueError('Invalid runtime autoload inventory')
    for name in inventory:
        safe_path(name)
    (root / 'runtime-autoload-files.json').write_bytes(autoload.stdout)
    results['runtimeAutoloadSha256'] = digest(autoload.stdout)
    results['runtimeAutoloadFileCount'] = len(inventory)
    results['complete'] = True
    (root / 'dependency-results.json').write_text(json.dumps(results, indent=2) + '\n')


def assemble(args):
    root = args.build.resolve(strict=True); plugin = root / 'plugin'
    receipt = json.loads((root / 'source-receipt.json').read_text())
    entries = verify_source(root, receipt)
    dependency = json.loads((root / 'dependency-results.json').read_text())
    if not dependency['complete'] or dependency['revision'] != receipt['revision'] or dependency['lockSha256'] != receipt['lockSha256']:
        raise ValueError('Successful exact dependency install/audit required')
    if any(dependency['steps'].get(name, {}).get('exitCode') != 0 for name in ['validate', 'install', 'audit']):
        raise ValueError('Dependency verification did not pass')
    inventory_bytes = (root / 'runtime-autoload-files.json').read_bytes()
    if digest(inventory_bytes) != dependency.get('runtimeAutoloadSha256'):
        raise ValueError('Runtime dependency autoload inventory changed')
    runtime_autoload = set(json.loads(inventory_bytes))
    lock = json.loads(entries['composer.lock'])
    vendor = plugin / 'vendor'
    if vendor.is_symlink() or (vendor / 'composer').is_symlink() or (vendor / 'composer/installed.json').is_symlink():
        raise ValueError('Linked dependency metadata')
    installed = json.loads((vendor / 'composer/installed.json').read_text())
    packages = validate_installed(lock, installed)
    excluded = []
    for file in sorted(plugin.rglob('*')):
        if file.is_dir() and not file.is_symlink():
            continue
        name = file.relative_to(plugin).as_posix(); parts = safe_path(name).parts
        if parts[0] != 'vendor':
            if name not in entries:
                raise ValueError('Unexpected generated file outside vendor: ' + name)
            continue
        if not retain_vendor_path(name, runtime_autoload):
            excluded.append(name); continue
        if file.is_symlink() or not file.is_file() or file.stat().st_size > 8 * 1024 * 1024:
            raise ValueError('Linked or oversized dependency file')
        if any(part.lower() == '.env' for part in parts) or file.suffix.lower() in {'.key', '.pem', '.sqlite', '.db'}:
            raise ValueError('Unexpected credential/data-shaped dependency file requires review')
        if len(parts) > 1 and parts[1] not in {'composer', 'autoload.php'} and '/'.join(parts[1:3]) not in packages:
            raise ValueError('Dependency file belongs to an unlisted package')
        entries[name] = file.read_bytes()
    if 'vendor/autoload.php' not in entries or not any(name.startswith('vendor/composer/') for name in entries):
        raise ValueError('Complete generated autoloader required')
    if not runtime_autoload.issubset(entries):
        raise ValueError('ZIP would omit a production-autoloaded runtime file')
    timestamp = commit_zip_time(receipt['sourceCommitEpoch'])
    if list(timestamp) != receipt['zipTimestampUtc']:
        raise ValueError('Source timestamp receipt changed')
    if args.previous_receipt:
        previous = json.loads(args.previous_receipt.read_text())
        previous_time = tuple(previous.get('zipTimestampUtc', [1980, 1, 1, 0, 0, 0]))
        if timestamp <= previous_time:
            raise ValueError('Successor source timestamp must advance for native opcode revalidation')
    data = zip_bytes(entries, timestamp)
    if digest(zip_bytes(entries, timestamp)) != digest(data):
        raise ValueError('Package build is not reproducible')
    output = args.output.resolve(); output.parent.mkdir(parents=True, exist_ok=True)
    with output.open('xb') as stream:
        stream.write(data)
    hashes = {name: digest(value) for name, value in sorted(entries.items())}
    vendor_hashes = {name: value for name, value in hashes.items() if name.startswith('vendor/')}
    result = {'schemaVersion': 1, 'revision': receipt['revision'], 'sourceArchiveSha256': receipt['archiveSha256'],
              'sourceCommitEpoch': receipt['sourceCommitEpoch'], 'zipTimestampUtc': timestamp,
              'lockSha256': receipt['lockSha256'], 'composerSha256': COMPOSER_SHA, 'builderImage': PHP_IMAGE,
              'packageSha256': digest(data), 'packageBytes': len(data), 'entries': hashes,
              'vendorTreeSha256': digest(json.dumps(vendor_hashes, sort_keys=True, separators=(',', ':')).encode()),
              'packages': packages, 'excludedDependencyPaths': excluded,
              'runtimeAutoloadFileCount': len(runtime_autoload),
              'retainedRuntimeUtilitiesUnderTestPaths': sorted(name for name in runtime_autoload if name.startswith('vendor/')
                  and any(part.lower() in VENDOR_EXCLUDED for part in PurePosixPath(name).parts[1:])),
              'nativeInstallAccepted': False, 'phpRuntimeAutoloadAccepted': False, 'oidcAccepted': False}
    with output.with_suffix('.receipt.json').open('x', encoding='utf-8') as file:
        file.write(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'assembled': True, 'zip': str(output), 'sha256': digest(data), 'entryCount': len(entries),
                      'runtimeAcceptancePending': True}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    prep = commands.add_parser('prepare'); prep.add_argument('--revision', required=True)
    prep.add_argument('--output', type=Path, required=True)
    prep.add_argument('--composer', type=Path, required=True)
    prep.add_argument('--docker-context', default='default', type=docker_context)
    build = commands.add_parser('assemble'); build.add_argument('--build', type=Path, required=True)
    build.add_argument('--output', type=Path, required=True)
    build.add_argument('--previous-receipt', type=Path, help='Require a later timestamp than the previously installed release')
    install = commands.add_parser('dependencies'); install.add_argument('--build', type=Path, required=True)
    args = parser.parse_args()
    if args.command == 'prepare':
        prepare(args)
    elif args.command == 'dependencies':
        dependencies(args)
    else:
        assemble(args)


if __name__ == '__main__':
    main()
