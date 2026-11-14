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
The adapter modules, bootstrap and entrypoint also match the previously tested
native build contexts. **No fresh native adapter image was built from this
public repository.** Native-image build acceptance remains separate from the
plugin ZIP's completed checks and native updates.

Unknown native bytes fail closed for OIDC and retain native password startup.
Vendor updates need a new reviewed profile and native/provider acceptance.
An application/plugin update is not a PostgreSQL or full UISP platform upgrade.
No production deployment, database restore, future-version certification or
redistribution of vendor images is included in this repository.
