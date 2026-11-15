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

Discover the existing API and CRM plugin-worker UID/GID independently. They can
differ, even on the same supported native version. Never change native accounts
or recursively change native data ownership to fit an adapter image.

Run this read-only helper against the target deployment, using its actual Docker
context and container names and a fresh local output path:

```text
python deployment/discover-runtime.py --docker-context CONTEXT --api-container API --crm-container CRM --output runtime-identity.json
```

It reads running API process identities, resolves the CRM `www-plugins` pool and
checks active plugin workers when present. It records exact container/image/start
identities and refuses ambiguous identities, root workers, changed owners or user
namespace remapping. No native application, account or session is modified. Keep
the receipt private and repeat discovery after a native runtime change.

Initialize four **new, dedicated, empty** Linux directories named `key`, `socket`,
`state` and `identity` beneath an operator-selected resource root. From a trusted
Linux provisioning environment with root ownership privileges and the reviewed
checkout available, run:

```text
node deployment/provision-runtime.cjs --initialize runtime-identity.json RESOURCE_ROOT
```

Only those dedicated resources are writable to the provisioning process. It
generates a fresh random installation key internally, sets ownership from the
discovered contract and refuses nonempty destinations. Do not use this initializer
to migrate an existing installation or regenerate its key.

| Resource | API access | CRM access | Fixed location and owner/mode |
| --- | --- | --- | --- |
| Installation key | Read-only | Read-only | `/run/secrets/ucrm-oidc-key`; discovered API owner, modes below |
| Dedicated socket | Read/write | Read-only | `/run/ucrm-oidc-adapter`; discovered API owner, modes below |
| Persistent private state | None | Read/write | `/var/lib/ucrm-oidc`; discovered CRM UID/GID, directory 0700 |
| Existing native CRM data | Read-only alias | Existing native mount | API alias `/opt/ucrm-oidc-crm-data` |
| Static policy/public CAs | None | Read-only | `/etc/ucrm-oidc`, operator-owned |
| Runtime identity contract | Read-only | None | `/etc/ucrm-oidc/runtime-identity.json`, root-owned 0444, parent 0555 |

When the UIDs match, the key uses the API UID/GID and mode 0400, its directory
0500, the socket directory 0700 and socket 0600. When UIDs differ, the key and
socket resources use the API UID and CRM GID: key 0440, key directory 0510,
socket directory **02710** and socket 0660. The setgid directory makes recreated
sockets inherit the CRM group; CRM can connect but cannot replace the socket.
No supplementary native group membership is added. Other trusted processes with
the same UID or authorized CRM group share this filesystem trust boundary.

Keep the generated key out of image builds, command arguments, environment and
logs. The key mount must not hide unrelated existing secrets. Keep state and key
across plugin removal and container replacement. Mount the identity directory
read-only into the API; CRM's separate network policy directory remains unchanged.
Startup validates the exact resource permissions and actual API process identity;
it does not silently repair ownership or fall back to a guessed UID.

For Docker named volumes, set `volume.nocopy: true` on **every consumer of each
prepared resource**, especially the initially empty socket and state volumes.
Otherwise Docker can copy the image directory's root ownership onto an empty
volume during container creation, invalidating the prepared permissions. For
example, the API socket mount uses the Compose long form:

```yaml
volumes:
  - type: volume
    source: oidc-socket
    target: /run/ucrm-oidc-adapter
    volume:
      nocopy: true
```

The CRM socket mount additionally uses `read_only: true`. Apply `nocopy` to the
isolated provisioning container's mounts too. Verify permissions **after**
container creation and prove the adapter status through CRM before enabling OIDC.

For an existing installation, stop new OIDC admission and drain plugin work before
an operator-reviewed resource migration. Preserve key bytes, encrypted state,
bindings and pending logout records. Scope any ownership adjustment to the
dedicated key/socket resources, retire only a proven stale owned socket, and
verify native password access, OIDC issuance and cleanup after replacement.

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
source. Keep new sign-ins disabled while saving configuration and testing discovery.
"Configured" means settings and the required secret are saved; discovery is a
separate check and does not establish credential validity, account matching,
native session issuance or logout.

The native adapter gates account lookup on the new-login switch, so protected
identity preview also requires that switch. When ready for a controlled test,
temporarily enable OpenID Connect login in native Settings and run **Preview
verified identity and native account match** as an administrator. Ordinary OIDC
login is available during this window. Preview itself never creates an account
link or native session. Disable new sign-ins again after the test if rollout is
not ready, including if the provider independently denies access. Test actual
session issuance and logout separately before leaving sign-ins enabled.

Settings and credential changes require authentication within five minutes.
Opening `/nms/login` while already signed in does not refresh the native session:
use the native account menu to sign out, then sign in again. The recovery page
opens that menu in a separate tab and provides a link back to reload settings
with the new session's CSRF token. With browser storage available, only non-secret
provider fields are retained in the original tab for 15 minutes, scoped to the
same administrator and provider revision. Re-enter client secrets. Nothing signs
out the administrator automatically or resubmits a pending change.

Register the exact displayed login and back-channel logout URLs with the provider.
Prove inbound signed logout delivery using normal server CA/hostname validation.
Outbound discovery success does not establish inbound callback reachability.

Opening the login URL automatically submits the protected same-origin start
form. After provider verification, the plugin automatically completes native
sign-in; neither step requires a button click. JavaScript is required. Healthy
sign-in pages show progress only, without administrator or password-login links.
Failures offer an explicit fresh attempt and native password login. History
restoration and uncertain session issuance never automatically retry a handoff.

A same-origin transition page opens
the validated provider authorization URL. This lets the provider use a separate
upstream login service without adding that service to the plugin's form-action
policy. If navigation stalls, recovery includes **Continue to provider**.
A stalled navigation offers recovery; it does not automatically retry sign-in.
Provider context/session failures must still be resolved at the provider.

Plugin pages use UISP typography, colors and controls. Login and recovery pages
follow the native responsive login layout and reference the installation's font
and background assets. Missing vendor assets fall back to system fonts and a
solid background; proprietary artwork and fonts are not included in the plugin.

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
