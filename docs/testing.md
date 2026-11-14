# Tests

The public preparation carries synthetic source tests. They do not contain real
credentials or contact an operational identity provider. Placeholder domains,
documentation IPs, loopback TLS servers and generated keys belong to fixtures.

## Source and artifact boundaries

```text
node --test adapter/test/adapter.test.cjs deployment/bootstrap.test.cjs
python deployment/plugin-package.test.py
```

These test authenticated transport, eligibility/receipt behavior, bounded replay,
source-hash/startup guards, login-page patching and deterministic ZIP boundaries.
They do not launch native containers.

## PHP

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
browser-runner interruption and successful continuation. A fresh native adapter
image build from this public repository remains a separate, unexecuted gate.
