# Operator installation and recovery

This describes the required integration. The exact public 0.3.1 plugin ZIP
passed the [listed staging acceptance](compatibility.md#public-031-package).
It is not a production deployment result or qualification of a newly built
native adapter image. Use a separate staging environment with synthetic
precreated staff accounts before deploying to your own installation.

## Prepare the native owner

1. Inventory the actual native service owner, exact image IDs/digests, command,
   UID/GID, mounts, network, proxy address and resource limits. Keep raw inspection
   private. Preserve native migrations, entrypoints, workers and device services.
2. Prove native password login, protected CRM/NMS access and logout before
   installing the integration. Retain an independent native administrator login.
3. Build an adapter image from an exact reviewed commit with the appropriate
   native profile and `--login-button`; omit `--canary` for a release. See
   [building](build.md). The build uses an operator-obtained pinned vendor image;
   no vendor image, native bundle or generated native configuration is published
   here. Do not upload vendor-containing derivative images as public assets.
4. Resolve every file bind against the original service owner's working
   directory. Require existing regular files and preserve all unrelated mounts,
   ports, environment and limits. Update only the API image for the adapter;
   latest `device-ws.sh` remains an unchanged separate native role.

## Provision once

Both supported native application processes use UID/GID 1000:1000; verify this
before provisioning. Use fresh resources and refuse nonempty destinations.

| Resource | API access | CRM access | Fixed location and owner/mode |
| --- | --- | --- | --- |
| Installation key | Read-only | Read-only | `/run/secrets/ucrm-oidc-key`, owner 1000:1000, file 0400, parent 0500 or 0700 |
| Dedicated socket | Read/write | Read-only | `/run/ucrm-oidc-adapter`, directory 0700, socket 0600, owner 1000:1000 |
| Persistent private state | None | Read/write | `/var/lib/ucrm-oidc`, owner 1000:1000, directory 0700 |
| Existing native CRM data | Read-only alias | Existing native mount | API alias `/opt/ucrm-oidc-crm-data` |
| Static policy/public CAs | None | Read-only | `/etc/ucrm-oidc`, operator-owned |

Generate a random 32-byte installation key as 64 lowercase hexadecimal characters
plus a newline, outside image builds, command arguments and environment variables.
Write it through stdin or a secret store; do not recursively change native data.
The key mount must not hide unrelated existing secrets. Keep state and key across
plugin removal and container replacement. CRM and API share the native UID, so
other trusted native PHP code shares this trust boundary.

The adapter reads native activation at
`/opt/ucrm-oidc-crm-data/ucrm/data/plugins/ucrm-oidc/data/config.json`.
Set `UCRM_OIDC_ADAPTER_ENABLED=1` only after the integration is provisioned and
native password recovery is verified. Keep native clustering enabled.

## Provider networking and callback privacy

Create a read-only `/etc/ucrm-oidc/network-policy.json` with schema:

```json
{"version":1,"trustedProxyAddresses":[],"privateOrigins":[]}
```

Populate `trustedProxyAddresses` with the exact immediate native proxy addresses
that overwrite `X-Real-IP`. Public HTTPS providers still require valid CA/hostname
verification, validated addresses and no redirects. A private issuer needs an
explicit `privateOrigins` entry with `origin`, approved `addresses`, and required
`caFile` naming an existing, readable operator-supplied public CA PEM file in the
same directory. The filename must end in `.pem` and contain only letters,
digits, underscores and hyphens before that suffix. Omitting it makes the
network policy unavailable; it does not select the system trust store. Give only
CRM the required provider egress; do not expose the adapter on TCP.

Before credentials or provider flows, use
`deployment/prepare-private-logging.py --help` to supply the exact native proxy,
CRM nginx and FPM source configuration files from the pinned images. The tool
verifies supported hashes and generates separate overlays; unknown inputs fail.

| Generated file | Read-only native mount target |
| --- | --- |
| `proxy-ucrm-locations.conf` | Proxy `/usr/local/openresty/nginx/templates/snippets/ucrm-locations.conf` |
| `proxy-nginx.conf.template` | Proxy `/usr/local/openresty/nginx/templates/nginx.conf.template` |
| `crm-nginx.conf` | CRM `/etc/nginx/nginx.conf` |
| `crm-server.conf` | CRM `/etc/nginx/available-servers/ucrm.conf` |
| `zzz-ucrm-oidc-privacy.conf` | CRM `/usr/local/etc/php-fpm.d/zzz-ucrm-oidc-privacy.conf` |

Mount source templates rather than startup-generated directories. Parse the
effective nginx/FPM configurations before activation and compare generated
hashes afterward. Protected callback paths suppress raw query/body/error logging;
ordinary diagnostics retain method, path, status and timing. Trusted clean form
responses may use `same-origin`; callbacks/errors default to `no-referrer`.
Do not globally disable unrelated diagnostics or weaken Origin/CSRF validation.
Use harmless markers to verify every proxy/application log layer before real
credentials, and prove native password/admin access remains functional.

## Native frontend configuration

Upload the qualified flat plugin ZIP through **System > Plugins**. Enable the
plugin, open its native Settings page and use the embedded provider form. Set the
issuer, client ID/authentication method, write-only secret and verified-email
source; test discovery and the protected preview before enabling new sign-ins.
Register the exact displayed login and back-channel logout URLs with the provider.
Prove inbound signed logout delivery using normal server CA/hostname validation.
Outbound discovery success does not establish inbound callback reachability.

Save login availability and the native execution schedule separately. Keep the
plugin enabled and select five-minute maintenance for pending native cleanup.
The new-login checkbox may be off while valid logout callbacks remain accepted.
Changing issuer/client registration stops trusting callbacks from the former
registration, so finish desired revocation before switching it.

## Updates and recovery

Preserve the installation key, external SQLite state, bindings and tombstones.
The same key encrypts state and authenticates native cleanup with separated
purposes; losing it is not repaired by changing the provider client secret.
Define operator key custody and a consistent SQLite/WAL recovery procedure.

For schema-1 to schema-2 upgrade, turn off the native new-login checkbox while
keeping the plugin enabled. Drain existing plugin requests/hooks and capture the
native FPM master/worker identities before a supported scoped graceful reload.
Prove captured old workers have retired; an arbitrary sleep is insufficient.
Upload through native UCRM, verify the actual new HTTP handler, run bounded native
maintenance until legacy/unindexed artifacts are clear, then enable admission.
No guessed client/session metadata or direct native token-row deletion is used.

The ZIP builder uses advancing commit-derived timestamps to avoid stale native
opcode caches. Verify HTTP behavior after every update. If recovery needs FPM
reload, scope it to the verified native master and preserve the service/data.
Schema 2 deliberately refuses old 0.2.2 readers; do not reset its marker or restore
old data to make incompatible code run. Recover with compatible code and retained
state/key, using native password login meanwhile.

Treat future UISP/PostgreSQL upgrades separately. Never mount newer PostgreSQL
data under an older image or assume an image rollback is a database rollback.
