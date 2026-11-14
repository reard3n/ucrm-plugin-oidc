"""Export a reviewed Git commit into a new allowlisted, credential-free context."""
from __future__ import annotations
import argparse
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import tarfile


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--revision', required=True)
    parser.add_argument('--profile', choices=['uisp-2.4.220', 'uisp-3.1.73'], required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--docker-context', default='default')
    parser.add_argument('--canary', action='store_true', help='Immutable synthetic-email restriction for the local native gate')
    parser.add_argument('--login-button', action='store_true', help='Include guarded public script tag after native gate and matching plugin asset review')
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[1]
    revision = subprocess.check_output(['git', '-C', str(repo), 'rev-parse', '--verify', f'{args.revision}^{{commit}}'], text=True).strip()
    if not re.fullmatch(r'[a-f0-9]{40}', revision):
        raise SystemExit('Expected reviewed Git commit')
    if not re.fullmatch(r'[A-Za-z0-9_.-]{1,64}', args.docker_context):
        raise SystemExit('Invalid Docker context name')
    required = [f'deployment/{name}' for name in ['Dockerfile', 'bootstrap.cjs', 'entrypoint.sh', 'compatibility.json']]
    required += [f'adapter/{name}.cjs' for name in ['index', 'native', 'protocol', 'identity']]
    archive = subprocess.check_output(['git', '-C', str(repo), 'archive', '--format=tar', revision, '--', *required])
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    (output / 'source.tar').write_bytes(archive)
    context = output / 'context'
    context.mkdir()
    files = {}
    with tarfile.open(fileobj=io.BytesIO(archive), mode='r:') as contents:
        for member in contents:
            relative = PurePosixPath(member.name)
            if relative.is_absolute() or '..' in relative.parts:
                raise SystemExit('Unsafe archive path')
            if member.isdir():
                (context / member.name).mkdir(parents=True, exist_ok=True)
                continue
            if not member.isfile() or member.name not in required:
                raise SystemExit('Unexpected archive member')
            data = contents.extractfile(member).read()
            target = context / member.name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
            files[member.name] = hashlib.sha256(data).hexdigest()
    if set(files) != set(required):
        raise SystemExit('Commit lacks required payload')
    manifest = json.loads((context / 'deployment/compatibility.json').read_text(encoding='utf-8'))
    profiles = [p for p in manifest['profiles'].values() if f"uisp-{p['nmsVersion']}" == args.profile]
    if len(profiles) != 1 or not re.fullmatch(r'ubnt/unms@sha256:[a-f0-9]{64}', profiles[0]['nmsImage']):
        raise SystemExit('Invalid pinned profile')
    profile = profiles[0]
    args_build = ['docker', '--context', args.docker_context, 'build', '--network', 'none', '--pull=false',
                  '--platform', 'linux/amd64', '--file', str(context / 'deployment/Dockerfile'),
                  '--build-arg', f'SOURCE_REVISION={revision}', '--build-arg', f'NATIVE_PROFILE={args.profile}',
                  '--build-arg', f"BASE_IMAGE={profile['nmsImage']}", '--build-arg',
                  f"CANARY_EMAIL_DOMAIN={'oidc229.example.com' if args.canary else ''}",
                  '--build-arg', f"INCLUDE_LOGIN_BUTTON={'1' if args.login_button else '0'}",
                  '--iidfile', str(output / 'image-id.txt'), str(context)]
    receipt = {'revision': revision, 'archiveSha256': hashlib.sha256(archive).hexdigest(), 'files': files,
               'profile': args.profile, 'baseImage': profile['nmsImage'], 'nativeCommand': profile['nativeCommand'],
               'canaryEmailDomain': 'oidc229.example.com' if args.canary else None,
               'loginButtonIncluded': args.login_button,
               'buildArgv': args_build, 'runtimeSecretsIncluded': False, 'buildExecuted': False}
    (output / 'source-receipt.json').write_text(json.dumps(receipt, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'revision': revision, 'context': str(context), 'receipt': str(output / 'source-receipt.json')}))


if __name__ == '__main__':
    main()
