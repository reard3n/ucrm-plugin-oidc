# Compatibility and acceptance boundary

| Native application | CRM runtime | Native API command |
| --- | --- | --- |
| UISP/NMS 2.4.220 | CRM 4.4.33 with an operator-provided PHP 8.2.35 bridge | `index.js` |
| UISP/NMS 3.1.73 | Official CRM 4.6.20 / PHP 8.3.36 | `api.sh` |

Exact native images, bundle hashes and source profiles are in
[compatibility.json](../deployment/compatibility.json). Stock CRM 4.4.33 with
PHP 8.1 is unsupported by the locked dependency graph. The custom older PHP
bridge is not distributed here. No version range or future vendor release is
accepted merely because its version falls within the native manifest bounds.

Previous isolated staging qualified the native issuer, native permissions/MFA,
current clustered startup and latest API/device process layout before OIDC
implementation. The unchanged 0.3.0 PHP payload passed 538 behavioral assertions
on PHP 8.2 and PHP 8.3, including real signatures, SQLite concurrency, logout
coordination, web boundaries and schema migration. Prior native/provider tests
also covered password recovery, settings administration, same-version lifecycle,
provider outage, native customer impersonation and signed Keycloak/AWACS
callbacks on both profiles. Normal and login-disabled notifications, deferred
cleanup, replay after CRM restart/replacement, preserved logout fences/state,
bounded log privacy and cleanup of owned sessions passed. That completed
functional evidence does not by itself accept the newly packaged public artifact.

## Public 0.3.1 package

The 0.3.1 release candidate passed package qualification, native frontend updates
and scoped provider login/logout acceptance on both listed profiles. This summary
contains public artifact identities and aggregate results; private runtime
records, keys, fixture ownership and original repository history are absent.
The same results are available as a
[machine-readable summary](../deployment/compatibility.json).

| Artifact | Identity |
| --- | --- |
| Release | [v0.3.1 prerelease, qualified in staging](https://github.com/reard3n/ucrm-plugin-oidc/releases/tag/v0.3.1) |
| Source commit used for the ZIP | `54da2a5803d5221ec0ece349c721009072d5e136` |
| Plugin version | `0.3.1` |
| ZIP SHA256 | `fc5537f9863cfec8a1b00300fcf0723a7a3e436f1313579906d0e464c06a5269` |
| Build receipt SHA256 | `6c75b44ed4f457253fb4e1a53d9beff0693b6a562b5ebcea2932caa22af8205f` |
| ZIP members | 996 |

Later documentation commits do not change this accepted package source or its
bytes. Build-time receipts remain immutable; the results below are subsequent
acceptance observations, not rewritten build flags.

Composer validation, locked production installation and dependency audit passed.
The extracted ZIP passed these checks on **each** of PHP 8.2.35 and PHP 8.3.36:

| Check | Passing count per PHP runtime |
| --- | ---: |
| PHP syntax | 884 files |
| Production classmap inventory | 842 entries |
| Actual plugin class loading | 9 classes |
| Behavioral assertions across 10 suites | 697 |

The behavioral suites cover core OIDC (112), logout-token verification (96),
logout coordination (56), concurrency (55), unlink races (8), web boundaries
(165), schema migration (46), native-session transport (107), client
authentication (37) and provider HTTP transport (15). Counts include related
assertions within each scenario; they are not 697 independent end-to-end flows.

An initial autoload diagnostic incorrectly required every optional library
Console class to load without its optional Symfony Console dependency. The
diagnostic was corrected to verify the classmap/file inventory, actual plugin
runtime classes and the behavioral suites. The package bytes did not change.

Both native profiles passed six frontend update checks: native administrator
login, vendor configuration preservation, embedded authorized provider settings,
displayed callback URLs, stable complete desktop/mobile layout, and owned-session
cleanup. Independent before/after readback matched all 996 installed files and
preserved the installation key, settings, account bindings, logout state and
unrelated native service identities/contracts.

The current profile then passed six fresh provider sign-ins, signed target
logout, preservation of nonmatching/native-password controls, and cleanup of
its owned native and provider sessions. On the latest profile, the browser
runner stalled while closing a context after three successful OIDC sessions
had been persisted. That preparation remains failed. The owned headless browser
was stopped, and a bounded continuation verified the same checkpoint, performed
one signed target logout, confirmed the surviving controls, and completed owned
cleanup. No login was repeated to conceal the interruption. This establishes
three latest-profile logins and their successful continuation, not a full
six-login latest preparation.

| Post-update smoke result | Current profile | Latest profile |
| --- | ---: | ---: |
| Fresh OIDC logins | 6 | 3 |
| Native password controls | 3 | 3 |
| Signed target logout and surviving-control verification | Passed | Passed |
| Owned native sessions cleaned | 9 | 6 |
| Owned provider sessions cleaned | 6 | 3 |
| Owned provider administrator cleanup | Passed | Passed |

All nine owned provider logout deliveries were acknowledged on their first
attempt. Final checks found no plugin session/context rows from these tests,
schema 2 active, legacy cleanup complete and no pending logout work in either
isolated environment. Earlier event/fence records were preserved.

Two bounded final privacy scans covered the current native log files and
CRM/API/proxy streams for both profiles, using 70 and 44 known search strings.
Neither found a credential match or compact-JWT pattern, and neither exceeded
its scan bound. Search counts include encoded variants, not distinct credentials.
No raw logs or credentials are published. An exact logout JWT was not supplied
to these scans; they do not prove every encoding or previously replaced log
container was covered.

The PHP runtime and dependency lock match the preceding qualified implementation
byte-for-byte; only package version/URL, licensing metadata and notices changed.
At the original v0.3.1 qualification, the adapter modules, bootstrap and entrypoint
matched the previously tested native build contexts; a fresh public-source image
had not yet been built. That historical package result remains unchanged. The
following successor acceptance qualifies the later adapter separately.

## Discovered service identities

The adapter from public commit `85982c5505032a78381b0d46442e9008661fa145`
removes the fixed native service UID assumption. Read-only discovery resolves the
running API identity and CRM plugin pool independently. A root-owned, read-only
contract controls narrowly scoped key/socket permissions; the native accounts,
groups and application data are not changed to fit the adapter.

Two immutable images were built without network access from that exact commit,
using the pinned vendor profiles and login-button integration without a canary
restriction. These are local image IDs, not public registry digests:

| Profile | Adapter image ID | Tested native service identities |
| --- | --- | --- |
| UISP 2.4.220 / CRM 4.4.33 | `sha256:131137a851021c53aad52a6178c7ec1f1ee2caac3560e428e4ec8d08cdeccc69` | API 1001:1001, CRM 1000:1000 |
| UISP 3.1.73 / CRM 4.6.20 | `sha256:a6a1bca57bfb81eeb400354b0f8ffdd331e6c9a3e669ae60b8abf48aba9e9db3` | API and CRM 1000:1000 |

The numeric values above are test arrangements, not deployment defaults. The
same transport passed isolated Linux cases with unequal arbitrary IDs, reversed
roles and a shared UID with different GIDs. All four arrangements passed two
socket generations, authenticated transport, invalid-MAC and unrelated-user
denial, fresh provisioning and nonempty-resource refusal. Separate-UID CRM
callers could not replace the key or socket. The source suites passed 32 Node
tests and six discovery tests, including both containers' namespace-map checks.

Both native profiles retained the exact 996-file qualified 0.3.1 ZIP. Each full
provider preparation passed six fresh OIDC logins across the two app registrations
and three native-password controls. Signed target logout passed on each profile,
with unchanged permissions and surviving password, other-user, other-session and
other-app controls. The split-UID profile also preserved all nine live controls
through API container replacement before the signed revocation. Keys, encrypted
settings and bindings survived; cleanup left zero plugin session/context rows and
no pending logout work in either lab. All 18 owned native and 12 provider sessions
from the successful preparations were cleaned.

The first attempt exposed Docker's empty-volume copy behavior: image-directory
metadata replaced prepared socket ownership, so the adapter refused activation
and native password login remained available. The failed attempt and its cleanup
were retained. Setting `volume.nocopy: true`, restoring only the dedicated socket
directory's planned ownership and repeating native acceptance resolved it. The
installation instructions require this setting on every prepared-volume consumer.
On the newer profile, the existing separate device service exited cleanly during
API replacement; its same container was restarted with its configuration intact.

No PHP package rebuild, production installation or future-version certification
is claimed by this adapter acceptance. Use the newer adapter source and the
updated provisioning instructions; the immutable v0.3.1 tag still contains the
older shared-UID adapter and its historical installation instructions.

Unknown native bytes fail closed for OIDC and retain native password startup.
Vendor updates need a new reviewed profile and native/provider acceptance.
An application/plugin update is not a PostgreSQL or full UISP platform upgrade.
No production deployment, database restore, future-version certification or
redistribution of vendor images is included in this repository.
