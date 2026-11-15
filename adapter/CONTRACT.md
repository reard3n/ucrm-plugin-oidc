# Native adapter protocol 2

Fixed socket `/run/ucrm-oidc-adapter/native-session.sock`; master secret
`/run/secrets/ucrm-oidc-key` is 64 lowercase hex characters, optional LF/CRLF.
Decode 32 bytes. HKDF-SHA256, empty salt, 32 output bytes, info
`ucrm-oidc:adapter-transport:v2` derives the transport key; info
`ucrm-oidc:adapter-receipt:v2` derives the cleanup receipt key.

One LF-terminated JSON frame per connection, maximum 16384 bytes excluding LF;
body decoded maximum 8192 bytes; timeout 5 seconds. Never retry `issue` after
an uncertain response. Start a new login after uncertainty.

Exact envelope fields:
`{v:2,caller:"ucrm-oidc",keyId:"installation-v1",at:<integer Unix seconds>,nonce:<64 lowercase hex>,body:<unpadded canonical base64url JSON>,mac:<64 lowercase hex>}`.
MAC input is LF-join of `UCRM-OIDC-ADAPTER-V2`, caller, keyId, decimal at,
nonce, body, with no trailing LF. Timestamp tolerance is 30 seconds.
No canonical JSON requirement beyond signing the actual serialized body bytes.
Nonce reservation precedes asynchronous work. Response is
`{ok:true,result:<DTO>}` or `{ok:false,error:{code:<fixed safe code>}}`.

Epoch and revision are 64 lowercase hex. Native IDs/artifacts use UUID strings.
Transactions use random 64 lowercase hex IDs. `audit` has exactly
`{remoteAddress:<IP literal>,userAgent:<0..256 chars without CR/LF/NUL>}`.
All operation objects have exact keys; no extra keys are accepted.

| operation | Other required fields |
| --- | --- |
| `status` | none |
| `resolve` | `email`, `serverEpoch`, `configRevision` |
| `inspect` | `nativeUserId`, `serverEpoch`, `configRevision` |
| `describe-caller` | `callerSessionId`, `audit`, `serverEpoch` |
| `issue` | `nativeUserId`, `transactionId`, `assertedAt`, `expiresAt`, `serverEpoch`, `configRevision`, `audit` |
| `complete-mfa` | `nativeUserId`, `transactionId`, `twoFactorToken`, `receipt`, `verificationCode`, `serverEpoch`, `configRevision`, `audit` |
| `revoke` | `nativeUserId`, `kind`, `artifact`, `receipt`, `serverEpoch` |

Issue assertion timestamps are integer Unix seconds, maximum lifetime 60s,
assertedAt no more than 30s in the future; expiresAt must be strictly future.
Configuration reads strict native `oidcEnabled` boolean from vendor-managed
`data/config.json`. Provider settings and credentials never enter that file.
Every request reads native `ucrm.plugin` for fixed name `ucrm-oidc`.
Status/describe/revoke remain available when OIDC configuration is disabled;
resolve/inspect/issue/complete require native plugin enabled and oidcEnabled.

DTOs:

```
status: {kind:'status',protocol:2,enabled:boolean,pluginEnabled:boolean,
         serverEpoch,configRevision:string|null,nativeVersion,sourceBundleSha256}
resolve/inspect: {kind:'user',user:{id,username,email,role,ucrmRole,
                 homeScreen,totpAuthEnabled,sessionTimeout,keepMeSignedIn}}
describe-caller: {kind:'caller',nativeUserId,username,role,ucrmRole,
                 createdAt:<Unix seconds>,source:'adapter'|'native-unattributed',
                 sessionId:<same supplied cookie>}
issue (including accounts with native TOTP enabled):
 {kind:'session',token,ucrmSessionId,cookieTtlMs,user:<same user projection>,
  createdAt:<native Unix seconds>,receipt:<opaque string>}
revoke: {kind:'revoked'}
```

`createdAt` means native token creation time, never independently proves local
password authentication. `describe-caller` does not grant CRM administration;
PHP independently requires native CRM current-user plugin-edit permission.
Its `ucrmRole` can be null, and it recognizes valid existing NMS-only or forced
reset callers for identity-mismatch detection even though OIDC admission would
deny them. Invalid, disabled and expired caller cookies return ADMISSION_DENIED;
AUTHENTICATION_FAILED refers to private transport authentication only.

The authenticated RP validates the OIDC identity before requesting issuance.
The provider owns authentication/MFA for this path. The adapter calls the native
session factory directly regardless of native TOTP enrollment, without changing
the account or the native password/MFA routes. The returned native pair is
validated and receipted before RP persistence/browser handoff.

`complete-mfa` remains recognized for protocol-2 compatibility but verifies its
receipt and fails with `MFA_EXPIRED`; it never issues a session. A fresh OIDC
login is required. As with any API-process replacement, incomplete legacy MFA
attempts cannot survive the upgrade. Legacy `mfa` receipts still permit exact
cleanup through `revoke`, including when login is disabled. PHP retains handling
for older adapters during staged upgrades. No attest-session operation exists.

Receipt is opaque and versioned, bound with dedicated-domain HMAC to native
UUID, artifact kind (`session` or `mfa`) and SHA256 of its exact value. It
authorizes deletion only, survives API restart, and is never browser auth.
Revoke is allowed for disabled native users and disabled/uninstalled plugin;
no valid-recent-session check is needed to delete the exact receipted artifact.
Master-key rotation invalidates old receipts unless the operator retains the
old verification key; key rotation is not silently implemented here.

Safe codes: BAD_REQUEST, AUTHENTICATION_FAILED, STALE_REQUEST, REPLAY, BUSY,
STALE_EPOCH, CONFIG_CHANGED, PLUGIN_INACTIVE, CONFIG_UNAVAILABLE, OIDC_DISABLED,
ADMISSION_DENIED, MFA_LOCAL_LOGIN_REQUIRED, MFA_INVALID, MFA_EXPIRED,
MFA_IN_PROGRESS, ASSERTION_EXPIRED, TRANSACTION_USED, RECEIPT_INVALID,
RATE_LIMITED, NATIVE_UNAVAILABLE. UI must not display raw native exceptions.

Immutable config `/opt/ucrm-oidc-adapter/config.json` fields:
`{protocol:2,profile:'uisp-2.4.220'|'uisp-3.1.73',sourceBundleSha256,runningBundleSha256,pluginName:'ucrm-oidc',pluginConfigPath:'/opt/ucrm-oidc-crm-data/ucrm/data/plugins/ucrm-oidc/data/config.json',canaryEmailDomain:'oidc229.example.com'|null}`.
Only packaging can select the canary domain; a web request cannot change it.
Activation requires `UCRM_OIDC_ADAPTER_ENABLED=1`; no NO_CLUSTER setting is used.
Latest package metadata identifies version 3.1.73 and its separate API process.
Install signature `install(server,{nativeMessages?})`; old native message
factories come from `server.plugins.messageHub.messages`, latest loader passes
the unchanged native factories. Bootstrap failure leaves native login running.
