# Tests

The public preparation carries synthetic source tests. They do not contain real
credentials or contact an operational identity provider. Placeholder domains,
documentation IPs, loopback TLS servers and generated keys belong to fixtures.

## Source and artifact boundaries

```text
node --test adapter/test/adapter.test.cjs adapter/test/identity.test.cjs deployment/bootstrap.test.cjs
python deployment/discover-runtime.test.py
python deployment/plugin-package.test.py
```

These test authenticated transport, eligibility/receipt behavior, bounded replay,
source-hash/startup guards, login-page patching and deterministic ZIP boundaries.
They do not launch native containers.

The identity tests reject missing, conflicting, root and remapped service
identities and exercise arbitrary, unequal UID/GID values. The isolated Linux
fixture `adapter/test/identity-linux.cjs` additionally uses real process identity
changes and Unix sockets. Run it only in a disposable root container with private
tmpfs mounts at `/run` and `/etc/ucrm-oidc`, a read-only checkout, no network and
`UCRM_OIDC_ISOLATED_IDENTITY_TEST=1`. It needs the normal root ownership/process
capabilities; vendor Node binaries with file capabilities also need their matching
bounding capability. Never mount deployment keys, state or sockets into this test.
It checks four identity arrangements, two socket generations each, authenticated
transport, wrong-MAC rejection, unrelated-user denial, a separate-UID client's
inability to replace the server socket/key, and refusal to initialize nonempty resources.

Native acceptance must separately exercise named-volume initialization and API
replacement. An empty socket volume needs Docker `nocopy` on all consumers so
image-directory metadata does not overwrite its prepared ownership. A unit or
tmpfs transport test cannot establish this Docker lifecycle behavior.

## PHP

For setup issues #2–#5, the focused regression commands are:

```text
php tests/setup-issues.php
php tests/web-unit.php
node tests/settings-draft-browser.cjs
```

The setup regression uses the real HTTP handler, application and native-session
authorization with synthetic transport/provider fixtures. It covers configuration
completeness versus admission, first-time disabled setup, stale/fresh sessions,
CSRF renewal, and the documented bounded-activation preview with no session/link
creation. Web tests cover the recovery UI and UTC audit formatting. The browser
test covers draft restoration, expiry, revision/user isolation, discarded drafts
and unavailable storage; secrets and authentication tokens are never retained.
These are focused regressions, not a fresh full native-platform qualification.

Use Linux PHP 8.2 and 8.3 with curl, JSON, mbstring, OpenSSL, PDO/SQLite and sodium.
Concurrency tests also need `pcntl`/process functions. Install the exact locked
production dependencies through the isolated build procedure, then point
`UCRM_OIDC_TEST_AUTOLOAD` at its `vendor/autoload.php`. The default path is
`plugin/vendor/autoload.php` for a developer's already qualified install.

Run each script separately so its assertions and cleanup complete:

```text
php tests/php-lint.php
php tests/core-unit.php
php tests/core-logout-verifier.php
php tests/logout-coordination.php
php tests/core-concurrency.php
php tests/core-unlink-race.php
php tests/store-migration.php
php tests/web-unit.php
php tests/native-session-unit.php
php tests/core-client-auth.php
php tests/core-transport.php
php tests/dns-live.php
```

The migration suite includes the original first-party schema-1 Store as an
isolated fixture. It verifies preservation and deliberate refusal of schema 2
by the older reader. The transport/authentication suites start bounded loopback
TLS helpers and use synthetic certificates/identities; no production endpoint is
required. Temporary databases and keys are created under the test process's
temporary directory and cleaned by its own fixture lifecycle.

For a release, repeat relevant suites against the **extracted ZIP's actual
vendor tree and first-party files**, not only a checkout. Record the exact ZIP,
source, lock, PHP versions and test results without secrets or private paths.

## Browser assets

For issue #7, generate actual HTTP response fixtures with
`php tests/start-transition-fixture.php > /private/path/start-fixture.json`, then
set `OIDC_START_FIXTURE` to that path and run
`node tests/start-transition-browser.cjs`. The fixture contains a freshly
generated test-only TLS key: keep it outside the repository and release ZIP.
The test serves the real handler's HTML/CSP through loopback HTTPS across three
origins. Chrome follows the issuer's redirects to a federated login and back for
normal and preview starts, with and without JavaScript. Stopping a stalled issuer
navigation must show recovery without submitting another start. `--expect-blocked` can reproduce
the old behavior using a response fixture generated before the fix.
Run `tests/web-unit.php` and `tests/setup-issues.php` for the related server-side
URL/Origin/CSRF/admin gates and real signed-provider/PKCE preview checks.

Install a reviewed Playwright development dependency and its browser separately
from the plugin's PHP dependencies. The default module name is `playwright`;
`OIDC229_PLAYWRIGHT_MODULE` can select an existing installation. These scripts
launch Chrome and intercept requests with synthetic responses:

```text
node tests/admin-zone-browser.cjs
node tests/web-browser-unit.cjs
```

## Native acceptance

Source tests do not establish native integration. Before release, use an isolated
native environment for both exact profiles and a separate provider. Verify
native passwords, staff roles/MFA, client impersonation, frontend settings,
verified-email matching, protected denials, normal logout, signed back-channel
logout, retry/fences, deferred native cleanup, provider outage and state/key
preservation through native lifecycle. Use fresh synthetic accounts, preserve
failed attempts, clean only owned sessions and inspect bounded logs without
publishing raw credentials or vendor source. The
[0.3.1 public-package acceptance summary](compatibility.md#public-031-package)
records the exact tested ZIP, 697 extracted-package assertions per PHP runtime,
native updates and scoped provider smoke results. It preserves the latest
browser-runner interruption and successful continuation. The later
[discovered-identity acceptance](compatibility.md#discovered-service-identities)
records fresh public-source adapter builds and their separate native checks.
