# Reproducible builds

Build from a reviewed committed revision, not mutable source mounts. Python 3,
Git, Docker with a local Linux/amd64 engine, and the qualified Composer PHAR are
required. The scripts accept an explicit Docker context; only local Unix sockets
or Windows named pipes may run dependency containers. No runtime/native service
is started by the source preparation commands.

Obtain [Composer 2.11.2](https://getcomposer.org/download/2.11.2/composer.phar)
from its official distribution and verify SHA256
`dd158c0afd41d15fac89e1b4e47b5d42911fe316c3687cd5edac98319b25d028`.
The [official download history](https://getcomposer.org/download/) lists this
version and digest. Use that exact version rather than a moving latest download;
the scripts reject another PHAR. Do not run `composer update`: preserve every
locked package/version/reference. The pinned native CRM builder image is recorded
in the packaging script; obtain it before a `--pull never` build. Its license and
distribution terms remain separate from this source repository.

## Plugin ZIP

Use a fresh output directory outside the checkout. On Docker Desktop, pass
`--docker-context desktop-linux`; otherwise use the explicit local context name.

```text
python deployment/plugin-package.py prepare --revision 54da2a5803d5221ec0ece349c721009072d5e136 --composer /path/to/composer.phar --docker-context default --output /path/to/new-build
python deployment/plugin-package.py dependencies --build /path/to/new-build
python deployment/plugin-package.py assemble --build /path/to/new-build --output /path/to/ucrm-oidc-0.3.1.zip --previous-receipt /path/to/installed-release.receipt.json
```

The dependency stage runs Composer validate/install/audit without plugins or
scripts, with production dependencies only and no inherited Composer credentials.
The output directory must be writable by the pinned build user 1000:1000; create
it with suitable ownership rather than making private directories world-writable.
Installation/audit needs access to public dependency distribution endpoints.
Autoload inventory runs separately without network access.

Assembly preserves source bytes, excludes private/generated configuration and
development dependency suites, includes supplied dependency notices, and rejects
lock drift or missing runtime files. Reusable production-autoloaded classes under
library `Test` namespaces are retained. The flat ZIP has commit-derived UTC
timestamps at two-second precision; `--previous-receipt` rejects nonadvancing
release timestamps. Omit that argument only for a genuinely first installation.

Keep source, dependency, file-hash and ZIP receipts. Build-time acceptance flags
remain false in that immutable receipt. Separate extracted-package/native
update acceptance records qualify those exact bytes; do not edit a frozen
receipt to change its verdict.
The [0.3.1 acceptance summary](compatibility.md#public-031-package) identifies the
qualified ZIP built from commit `54da2a5803d5221ec0ece349c721009072d5e136`.
Later documentation commits do not identify a rebuild of those same bytes;
use the pinned revision above to reproduce the accepted package, and qualify
any package built from another source revision separately.

## Native adapter image

```text
python deployment/prepare-build-context.py --revision HEAD --profile uisp-3.1.73 --login-button --docker-context default --output /path/to/new-native-build
```

For the older qualified profile use `uisp-2.4.220`. The source receipt contains
the exact `buildArgv` array. Review and execute it as subprocess arguments, never
as a shell-concatenated string. The image build is network-disabled, uses a pinned
base already present locally, and receives no runtime keys or provider secrets.
`--canary` restricts the adapter to synthetic accounts and is only for initial
native qualification; release builds omit it.

The image keeps pristine/generated native bytes for guarded startup and recovery.
Unknown hashes fail closed. This repository supplies the patcher and adapter,
not complete native bundles or redistributable vendor images. Qualify the built
image with native password/MFA/permission and process-lifecycle checks before
promotion. The 0.3.1 plugin ZIP passed its documented checks; a fresh native
adapter image build from this public repository has not been executed or accepted.
