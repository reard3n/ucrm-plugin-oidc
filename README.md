# UCRM OpenID Connect

Sign in to existing UISP and UCRM staff accounts through an OpenID Connect
provider. UCRM supplies the configuration interface. The native applications
continue to issue and validate sessions, enforce permissions and MFA, and own
session expiration and local logout.

The **0.3.1 release candidate has passed package qualification, native frontend
updates and scoped provider login/logout checks** on both listed profiles.
Download the [staging-qualified v0.3.1 prerelease](https://github.com/reard3n/ucrm-plugin-oidc/releases/tag/v0.3.1).
See the [acceptance summary](docs/compatibility.md#public-031-package) for the
exact package hashes, completed checks and test limits. Runtime implementation and locked
dependencies are unchanged from the preceding tested 0.3.0 candidate. Native
adapter source matches the qualified integration, but a fresh public native-image
build has not been executed. Operational records and credentials are not published.
First-party source is available under the [MIT license](LICENSE), also included
in the packaged plugin. Bundled dependencies retain their own license notices.

## Behavior

- Authenticate precreated staff accounts using unique verified email matching,
  then retain a stable issuer/subject binding. Do not create accounts or change
  native profiles, groups or permissions.
- Use authorization code, PKCE, state, nonce, maintained JOSE validation and
  bounded HTTPS discovery/token/UserInfo requests.
- Configure provider settings, credentials, connection tests, login availability,
  account bindings and audit through the native plugin Settings page.
- Accept signed OpenID Connect Back-Channel Logout notifications and revoke only
  matching plugin-issued native sessions. Durable cleanup survives an unavailable
  native adapter. Provider token expiry alone does not terminate native sessions.
- Keep native password login as the recovery path.

Installation requires a one-time operator setup of the native session adapter,
private socket/key/state mounts and callback logging protection. Uploading the
plugin ZIP alone cannot call the native session issuer.

Read [installation and recovery](docs/installation.md),
[architecture](docs/architecture.md), [compatibility](docs/compatibility.md),
[build instructions](docs/build.md) and [tests](docs/testing.md).
The repository contains source and tests, not vendor native images or credentials.
The plugin ZIP bundles the locked PHP dependencies; UCRM performs no Composer
download during installation or login. See [third-party notices](plugin/NOTICE.md).
