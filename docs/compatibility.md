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

The **0.3.1 public source/package preparation is pending build, dependency audit,
extracted-package checks and native update acceptance**. Public acceptance
flags stay false until those checks are recorded for the exact release bytes.
Private runtime records, keys, fixture ownership and original repository history
are intentionally absent.

Unknown native bytes fail closed for OIDC and retain native password startup.
Vendor updates need a new reviewed profile and native/provider acceptance.
An application/plugin update is not a PostgreSQL or full UISP platform upgrade.
No production deployment, database restore, future-version certification or
redistribution of vendor images is included in this repository.
