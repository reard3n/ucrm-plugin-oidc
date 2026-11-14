<?php
declare(strict_types=1);
namespace UcrmOidc;

// Run in its own PHP process: doubles test HTTP authorization/projection only.
// Native transport and real OIDC library behavior have separate integration gates.
final class NativeSessionException extends \RuntimeException
{
    public function __construct(public readonly string $safeCode) { parent::__construct($safeCode); }
}
final class NativeSession
{
    public bool $authorized = true;
    public ?array $currentUser = null;
    public int $adminChecks = 0;
    public int $currentChecks = 0;
    public array $context = ['nativeUserId' => '11111111-1111-4111-8111-111111111111', 'sessionId' => '22222222-2222-4222-8222-222222222222', 'username' => 'unit-admin'];
    public function servingOrigin(array $server): string { return 'https://crm.example.test'; }
    public function audit(array $server): array { return ['remoteAddress' => '192.0.2.229', 'userAgent' => 'unit']; }
    public function adminContext(array $cookies, array $server): array { ++$this->adminChecks; if (!$this->authorized) throw new NativeSessionException('ADMISSION_DENIED'); return $this->context; }
    public function current(array $cookies, array $server): ?array { ++$this->currentChecks; return $this->currentUser; }
}
final class Application
{
    public NativeSession $session;
    public bool $fresh = true;
    public bool $ready = true;
    public int $pendingCleanup = 0;
    public array $calls = [];
    public array $completionVm;
    public array $handoffVm;
    public array $logoutVm = ['ok' => true];
    public ?string $callbackUrl = null;
    public ?string $backchannelLogoutUrl = null;
    public bool $legacyCleanupPending = false;
    public ?\Throwable $failure = null;
    public function __construct() {
        $this->session = new NativeSession();
        $this->completionVm = ['kind' => 'session', 'returnPath' => '/crm/'];
        $this->handoffVm = ['kind' => 'session', 'token' => '33333333-3333-4333-8333-333333333333', 'ucrmSessionId' => '44444444-4444-4444-8444-444444444444', 'cookieTtlMs' => null, 'returnPath' => '/crm/'];
    }
    public function native(): NativeSession { return $this->session; }
    public function status(): array { return ['enabled' => $this->ready, 'ready' => $this->ready, 'loginLabel' => 'Provider <script>bad</script>', 'secret' => 'NEVER_RENDER']; }
    public function authorizationOrigins(): array { return ['https://idp.example.test']; }
    public function configuration(array $context): array { return ['settings' => Config::DEFAULTS, 'providerRevision' => 2, 'credentialRevision' => 3, 'secretPresent' => true, 'callbackUrl' => $this->callbackUrl, 'backchannelLogoutUrl' => $this->backchannelLogoutUrl, 'legacyCleanupPending' => $this->legacyCleanupPending, 'native' => ['enabled' => false, 'pluginEnabled' => true, 'nativeVersion' => 'unit', 'nativeConfigRevision' => null], 'ready' => false]; }
    public function csrf(string $binding, string $purpose): string { return hash('sha256', $binding . ':' . $purpose); }
    public function checkCsrf(string $binding, string $purpose, string $token): void { if (!hash_equals($this->csrf($binding, $purpose), $token)) throw new AppException('CSRF_DENIED', 403); }
    public function assertFresh(array $context): void { if (!$this->fresh) throw new AppException('RECENT_AUTH_REQUIRED', 403); }
    private function record(string $name, array $arguments): array { if ($this->failure) throw $this->failure; $this->calls[] = [$name, $arguments]; return []; }
    public function saveSettings(array $context, array $input): array { return $this->record('settings', $input); }
    public function replaceSecret(array $context, array $input): array { return $this->record('secret-replace', $input); }
    public function clearSecret(array $context, array $input): array { return $this->record('secret-clear', $input); }
    public function connectionTest(array $context): array { return $this->record('test', []); }
    public function setup(array $context): array { return $this->record('setup', []); }
    public function accountLookup(array $context, string $email): array { $this->record('lookup', ['email' => $email]); return ['nativeUserId' => '55555555-5555-4555-8555-555555555555', 'username' => 'existing-user', 'email' => $email]; }
    public function unlink(array $context, array $input): array { $this->record('unlink', $input); return ['pendingCleanup' => $this->pendingCleanup]; }
    public function relink(array $context, array $input): array { return $this->record('relink', $input); }
    public function records(array $context, string $kind, array $query): array {
        $this->record('records', ['kind' => $kind] + $query);
        $items = $kind === 'bindings' ? [['id' => str_repeat('a', 64), 'issuer' => 'https://idp.example.test', 'subject' => '<img src=x onerror=bad>', 'nativeUserId' => 'hidden-native-id', 'username' => 'existing-user', 'active' => true, 'version' => 7, 'createdAt' => 1, 'updatedAt' => 2]]
            : [['id' => 1, 'event' => '<script>bad</script>', 'at' => 1, 'actor' => 'hash-a', 'object' => 'hash-b', 'outcome' => 'passed']];
        return ['items' => $items, 'total' => 26, 'page' => $query['page'], 'pageSize' => 25];
    }
    public function start(string $browser, string $return, array $audit, ?array $preview = null, bool $fresh = false): array { $this->record('start', compact('browser', 'return', 'audit', 'preview', 'fresh')); return ['flowId' => str_repeat('f', 64), 'authorizationUrl' => 'https://idp.example.test/authorize?state=synthetic-state']; }
    public function callback(string $browser, array $parameters, array $audit): array { $this->record('callback', $parameters); return ['flowId' => str_repeat('f', 64)]; }
    public function backchannelLogout(string $logoutToken, array $audit): array { $this->record('backchannel-logout', compact('logoutToken', 'audit')); return $this->logoutVm; }
    public function completion(string $browser, string $flow): array { $this->record('completion', []); return $this->completionVm; }
    public function handoff(string $browser, string $flow, array $audit, ?array $current): array { $this->record('handoff', compact('current', 'audit')); return $this->handoffVm; }
    public function completeMfa(string $browser, string $flow, string $otp, array $audit, ?array $current): array { $this->record('mfa-complete', compact('otp', 'current')); return $this->handoffVm; }
}

if (!class_exists(Config::class, false)) {
    require __DIR__ . '/../plugin/src/AppException.php';
    require __DIR__ . '/../plugin/src/Config.php';
    require __DIR__ . '/../plugin/src/Web.php';
}
$passed = 0;
function check(bool $value, string $name): void { global $passed; if (!$value) { fwrite(STDERR, "FAIL: $name\n"); exit(1); } ++$passed; }
function has(string $body, string $text): bool { return str_contains($body, $text); }
$app = new Application(); $web = new Web($app, 9);
$server = ['REQUEST_METHOD' => 'GET', 'QUERY_STRING' => '', 'HTTP_HOST' => 'crm.example.test'];
$postServer = $server + ['HTTP_ORIGIN' => 'https://crm.example.test', 'CONTENT_TYPE' => 'application/x-www-form-urlencoded']; $postServer['REQUEST_METHOD'] = 'POST';
$browser = str_repeat('b', 64); $flow = str_repeat('f', 64); $cookies = [Web::BROWSER_COOKIE => $browser];
$adminCsrf = $app->csrf($app->session->context['sessionId'], 'admin');
$flowCsrf = $app->csrf($browser, 'flow:' . $flow);
$post = fn(string $action, array $values = []) => $web->handle($postServer, ['action' => $action], ['csrf' => $adminCsrf] + $values, $cookies);

$response = $web->handle($server, [], [], []);
check($response['status'] === 200, 'initial setup works before provider configuration');
check(has($response['body'], '/crm/system/plugins/9/configuration'), 'native enable configuration link uses only plugin integer');
check(has($response['body'], 'name="clientSecret"') && has($response['body'], 'value=""'), 'secret form always blank');
check(!has($response['body'], 'NEVER_RENDER'), 'unprojected secret never rendered');
check(has($response['body'], 'RFC 6901 JSON pointer'), 'nested claim configuration explained');
check($response['headers']['Cache-Control'] === 'no-store, max-age=0' && $response['headers']['Referrer-Policy'] === 'same-origin', 'clean admin form preserves exact POST origin without cross-origin referrer');
check(has($response['headers']['Content-Security-Policy'], "form-action 'self';") && !has($response['headers']['Content-Security-Policy'], 'unsafe-inline'), 'admin restrictive CSP');
$app->session->authorized = false;
foreach (['admin', 'bindings', 'audit'] as $route) { check($web->handle($server, ['action' => $route], [], [])['status'] === 403, 'native permission required for ' . $route); }
check($post('settings')['status'] === 403 && count($app->calls) === 0, 'native denial prevents writes');
$app->session->authorized = true;
$metadata = $web->handle($server, ['action' => 'status'], [], []);
check(array_keys(json_decode($metadata['body'], true)) === ['enabled', 'ready', 'loginLabel', 'startPath'], 'anonymous metadata exact projection');
check(!has($metadata['body'], 'NEVER_RENDER'), 'anonymous metadata no secret');
foreach (['DELETE', 'PUT', 'HEAD'] as $method) { check($web->handle(['REQUEST_METHOD' => $method] + $server, ['action' => 'status'], [], [])['status'] === 405, 'method map denies ' . $method); }
check($web->handle($server, ['action' => 'settings'], [], [])['status'] === 405, 'GET cannot write settings');
check($web->handle($server, ['action' => 'unknown'], [], [])['status'] === 404, 'unknown route denied');
check($web->handle($postServer, ['action' => 'setup'], [], $cookies)['status'] === 403, 'missing CSRF denied');
$wrongOrigin = $postServer; $wrongOrigin['HTTP_ORIGIN'] = 'https://attacker.example.test';
check($web->handle($wrongOrigin, ['action' => 'setup'], ['csrf' => $adminCsrf], $cookies)['status'] === 403, 'foreign Origin denied even with CSRF');
unset($wrongOrigin['HTTP_ORIGIN']);
check($web->handle($wrongOrigin, ['action' => 'setup'], ['csrf' => $adminCsrf], $cookies)['status'] === 403, 'missing Origin denied');
$jsonServer = $postServer; $jsonServer['CONTENT_TYPE'] = 'application/json';
check($web->handle($jsonServer, ['action' => 'setup'], ['csrf' => $adminCsrf], $cookies)['status'] === 415, 'unsupported content type denied');
check($post('setup', ['targetUuid' => 'injected'])['status'] === 400, 'unexpected admin field denied');
check($post('secret-replace', ['expectedCredentialRevision' => ['3']])['status'] === 400, 'nested form value denied');
check($web->handle(['CONTENT_LENGTH' => '32769'] + $postServer, ['action' => 'setup'], ['csrf' => $adminCsrf], $cookies)['status'] === 413, 'oversized POST denied');
check($web->handle(['QUERY_STRING' => 'action=status&action=admin'] + $server, ['action' => 'status'], [], [])['status'] === 400, 'duplicate raw query denied');
$app->fresh = false;
foreach (['settings', 'secret-replace', 'secret-clear', 'unlink', 'relink'] as $action) { check($post($action)['status'] === 403, 'recent authentication required for ' . $action); }
check($post('setup')['status'] === 200, 'setup diagnostics do not require fresh authentication');
check($post('test')['status'] === 200, 'discovery test does not require fresh authentication');
check($post('lookup', ['email' => 'existing@example.test', 'bindingId' => str_repeat('a', 64), 'expectedVersion' => '7'])['status'] === 200, 'native lookup requires permission but not freshness');
$app->fresh = true;
$settings = Config::DEFAULTS; $settings['maxAge'] = '0'; $settings['endpointOrigins'] = "https://one.example.test\r\nhttps://two.example.test\n";
$result = $post('settings', ['expectedProviderRevision' => '2'] + $settings);
check($result['status'] === 200, 'settings form normalization succeeds');
$call = end($app->calls)[1];
check($call['expectedProviderRevision'] === 2 && $call['maxAge'] === 0, 'revision and maxAge use strict integers');
check($call['endpointOrigins'] === ['https://one.example.test', 'https://two.example.test'], 'endpoint origins split into exact array');
check($post('secret-clear', ['expectedCredentialRevision' => '03'])['status'] === 400, 'ambiguous revision denied');
check($post('secret-replace', ['expectedCredentialRevision' => '3', 'clientSecret' => 'PRIVATE_TEST_SECRET'])['status'] === 200, 'secret replacement accepted');
check(!has($post('secret-replace', ['expectedCredentialRevision' => '3', 'clientSecret' => 'PRIVATE_TEST_SECRET'])['body'], 'PRIVATE_TEST_SECRET'), 'submitted secret is never reflected');
$app->failure = new \RuntimeException('PRIVATE_PROVIDER_RESPONSE');
$response = $post('test');
check($response['status'] === 503 && !has($response['body'], 'PRIVATE_PROVIDER_RESPONSE'), 'unexpected exception redacted');
$app->failure = null;
$app->pendingCleanup = 1;
check(has($post('unlink', ['bindingId' => str_repeat('a', 64), 'expectedVersion' => '7'])['body'], 'still pending'), 'unlink reports pending native cleanup honestly');
$app->pendingCleanup = 0;
check(has($post('unlink', ['bindingId' => str_repeat('a', 64), 'expectedVersion' => '7'])['body'], 'sessions is complete'), 'unlink reports completed retained cleanup');

$start = $web->handle($server, ['action' => 'start'], [], []);
check($start['status'] === 200 && count($start['cookies']) === 1, 'GET start issues browser correlation only');
$cookie = $start['cookies'][0];
check($cookie['name'] === '__Host-ucrm-oidc-browser' && $cookie['options']['path'] === '/' && !isset($cookie['options']['domain']) && $cookie['options']['secure'] && $cookie['options']['httponly'] && $cookie['options']['samesite'] === 'Lax', 'host-only correlation cookie prevents parent-domain shadowing');
check(!has($start['body'], '<script>bad</script>') && has($start['body'], '&lt;script&gt;'), 'provider label escaped');
check(has($start['headers']['Content-Security-Policy'], "form-action 'self' https://idp.example.test;") && !has($start['headers']['Content-Security-Policy'], " https:;"), 'start CSP only configured provider origins');
$second = $web->handle($server, ['action' => 'start'], [], $cookies);
check($second['cookies'][0]['value'] === $browser, 'concurrent starts retain browser binding');
$before = count($app->calls);
check($web->handle($postServer, ['action' => 'start'], ['csrf' => 'invalid'], $cookies)['status'] === 403 && count($app->calls) === $before, 'CSRF prevents flow creation');
$startCsrf = $app->csrf($browser, 'flow:start');
$startPost = $web->handle($postServer, ['action' => 'start'], ['csrf' => $startCsrf, 'return' => '/nms/', 'fresh' => '1', 'preview' => '0'], $cookies);
check($startPost['status'] === 303 && str_starts_with($startPost['headers']['Location'], 'https://idp.example.test/'), 'CSRF POST starts provider redirect');
check(end($app->calls)[1]['fresh'] === true, 'fresh flag passed to core');
foreach (['//attacker.test/', '/crm/../logout', '/nms/%2f%2fattacker', '/crm/_plugins/anything', '/nms/api/v2/user', '/crm/login'] as $return) { check($web->handle($server, ['action' => 'start', 'return' => $return], [], $cookies)['status'] === 400, 'unsafe return rejected ' . $return); }
$app->session->authorized = false;
check($web->handle($server, ['action' => 'start', 'preview' => '1'], [], $cookies)['status'] === 403, 'preview start requires current admin');
$app->session->authorized = true;
$callback = $web->handle($server, ['action' => 'callback', 'code' => 'PRIVATE_CODE', 'state' => 'STATE'], [], $cookies);
check($callback['status'] === 303 && $callback['headers']['Location'] === Config::ENTRY . '?action=complete&flow=' . $flow, 'callback removes code and state from navigation');
check(!has($callback['body'], 'PRIVATE_CODE') && !has($callback['headers']['Location'], 'PRIVATE_CODE'), 'callback code never rendered');
$missingBrowser = $web->handle($server, ['action' => 'callback', 'code' => 'PRIVATE_CODE'], [], []);
check($missingBrowser['status'] === 303 && $missingBrowser['headers']['Location'] === Config::ENTRY . '?action=error&reason=BROWSER_BINDING_REQUIRED', 'callback correlation failure redirects without code');
$app->failure = new AppException('ADMISSION_DENIED', 403);
$deniedCallback = $web->handle($server, ['action' => 'callback', 'code' => 'PRIVATE_CODE'], [], $cookies);
check($deniedCallback['status'] === 303 && !has($deniedCallback['headers']['Location'], 'PRIVATE_CODE') && $deniedCallback['body'] === '', 'denied callback removes authorization code and state');
$deniedPage = $web->handle($server, ['action' => 'error', 'reason' => 'ADMISSION_DENIED'], [], $cookies);
check($deniedPage['status'] === 403 && has($deniedPage['body'], 'pre-created native staff account') && !has($deniedPage['body'], 'edit plugins'), 'unmatched staff clean error has account eligibility message');
foreach (['VERIFIED_EMAIL_REQUIRED' => 'verified email address', 'BINDING_CONFLICT' => 'different account link', 'FLOW_EXPIRED' => 'Start a new sign-in', 'FLOW_CONFIGURATION_CHANGED' => 'Start a new sign-in', 'PROVIDER_UNAVAILABLE' => 'provider could not be reached'] as $code => $message) {
    $app->failure = new AppException($code, 403);
    $redirected = $web->handle($server, ['action' => 'callback', 'code' => 'PRIVATE_CODE'], [], $cookies);
    check($redirected['status'] === 303 && str_ends_with($redirected['headers']['Location'], 'reason=' . $code), 'safe callback reason ' . $code);
    check(has($web->handle($server, ['action' => 'error', 'reason' => $code], [], $cookies)['body'], $message), 'actionable safe message ' . $code);
}
$app->failure = new \RuntimeException('PRIVATE_PROVIDER_RESPONSE');
$unexpectedCallback = $web->handle($server, ['action' => 'callback', 'code' => 'PRIVATE_CODE'], [], $cookies);
check($unexpectedCallback['headers']['Location'] === Config::ENTRY . '?action=error&reason=REQUEST_FAILED', 'unknown callback exceptions use a fixed clean reason');
check($web->handle($server, ['action' => 'error', 'reason' => 'PRIVATE_PROVIDER_RESPONSE'], [], $cookies)['status'] === 400, 'error route rejects nonallowlisted reasons');
check(!has($web->handle($server, ['action' => 'error', 'reason' => '<script>bad</script>'], [], $cookies)['body'], '<script>bad</script>'), 'error route never reflects arbitrary content');
$app->failure = null;

$complete = $web->handle($server, ['action' => 'complete', 'flow' => $flow], [], $cookies);
check($complete['status'] === 200 && has($complete['body'], 'id="oidc-handoff"'), 'verified flow renders explicit native handoff');
check(!has($complete['body'], $app->handoffVm['token']) && !has($complete['body'], $app->handoffVm['ucrmSessionId']), 'completion HTML contains no native pair');
$app->completionVm['kind'] = 'mfa';
$mfaPage = $web->handle($server, ['action' => 'complete', 'flow' => $flow], [], $cookies);
check(has($mfaPage['body'], 'id="oidc-handoff" hidden') && !has($mfaPage['body'], 'id="oidc-mfa" hidden'), 'reload resumes native MFA form without reissuing');
$app->completionVm = ['kind' => 'preview', 'previewRequiresAdminId' => $app->session->context['nativeUserId'], 'preview' => ['issuer' => 'https://idp.example.test', 'subject' => '<script>bad</script>', 'email' => 'existing@example.test', 'emailVerified' => true, 'username' => 'existing', 'role' => 'admin', 'ucrmRole' => null, 'alreadyLinked' => false]];
$preview = $web->handle($server, ['action' => 'complete', 'flow' => $flow], [], $cookies);
check($preview['status'] === 200 && !has($preview['body'], $app->session->context['nativeUserId']) && !has($preview['body'], '<script>bad</script>'), 'authorized preview projects safely and hides admin UUID');
$app->completionVm['previewRequiresAdminId'] = 'different';
check($web->handle($server, ['action' => 'complete', 'flow' => $flow], [], $cookies)['status'] === 403, 'preview rechecks same original administrator');
$before = count($app->calls);
check($web->handle($postServer, ['action' => 'handoff'], ['csrf' => 'wrong', 'flow' => $flow], $cookies)['status'] === 403 && count($app->calls) === $before, 'handoff CSRF checked before issuance');
check($web->handle($postServer, ['action' => 'handoff'], ['csrf' => $flowCsrf, 'flow' => $flow, 'nativeUserId' => 'injected'], $cookies)['status'] === 400, 'browser cannot select native identity');
$app->session->currentUser = ['nativeUserId' => 'existing-current'];
$handoff = $web->handle($postServer, ['action' => 'handoff'], ['csrf' => $flowCsrf, 'flow' => $flow], $cookies);
check($handoff['status'] === 200 && $handoff['headers']['x-auth-token'] === $app->handoffVm['token'], 'native token only in response header');
check(!has($handoff['body'], $app->handoffVm['token']) && !has($handoff['body'], $app->handoffVm['ucrmSessionId']), 'native artifacts absent JSON');
check(end($app->calls)[1]['current'] === $app->session->currentUser, 'core receives native current identity for mismatch guard');
$nativeCookie = $handoff['cookies'][0];
check($nativeCookie['name'] === 'nms-session' && $nativeCookie['options']['expires'] === 0 && $nativeCookie['options']['path'] === '/', 'native session cookie has native session lifetime');
check($nativeCookie['options']['secure'] && $nativeCookie['options']['httponly'] && $nativeCookie['options']['samesite'] === 'Lax', 'native cookie attributes preserved');
$app->handoffVm['cookieTtlMs'] = 600000;
$timed = $web->handle($postServer, ['action' => 'handoff'], ['csrf' => $flowCsrf, 'flow' => $flow], $cookies);
check(abs($timed['cookies'][0]['options']['expires'] - time() - 600) <= 1, 'native persistent lifetime preserved');
$app->handoffVm['returnPath'] = '//attacker.example.test/';
$malformed = $web->handle($postServer, ['action' => 'handoff'], ['csrf' => $flowCsrf, 'flow' => $flow], $cookies);
check($malformed['status'] === 400 && !$malformed['cookies'] && !isset($malformed['headers']['x-auth-token']), 'malformed artifact DTO never emits any session artifact');
$app->handoffVm = ['kind' => 'mfa', 'twoFactorToken' => 'MUST_STAY_SERVER_SIDE'];
$mfa = $web->handle($postServer, ['action' => 'handoff'], ['csrf' => $flowCsrf, 'flow' => $flow], $cookies);
check($mfa['body'] === '{"ok":true,"kind":"mfa"}' && !$mfa['cookies'] && !isset($mfa['headers']['x-auth-token']), 'MFA challenge never sent to browser');
check($web->handle($postServer, ['action' => 'mfa-complete'], ['csrf' => $flowCsrf, 'flow' => $flow, 'otp' => '12345'], $cookies)['status'] === 400, 'invalid OTP shape rejected before native call');
$mfa = $web->handle($postServer, ['action' => 'mfa-complete'], ['csrf' => $flowCsrf, 'flow' => $flow, 'otp' => '123456'], $cookies);
check($mfa['status'] === 200 && end($app->calls)[1]['otp'] === '123456' && !has($mfa['body'], '123456'), 'OTP goes to native completion only');
$bindings = $web->handle($server, ['action' => 'bindings'], [], $cookies);
check(has($bindings['body'], 'page=2') && !has($bindings['body'], '<table'), 'bindings use server pagination and native-style lists');
check(!has($bindings['body'], '<img src=x') && !has($bindings['body'], 'hidden-native-id'), 'binding display escapes subject and omits internal UUID');
$audit = $web->handle($server, ['action' => 'audit'], [], $cookies);
check(!has($audit['body'], '<script>bad</script>') && has($audit['body'], 'hash-a'), 'audit safe projection');
foreach ([$start, $bindings, $audit, $result] as $formPage) {
    check($formPage['headers']['Referrer-Policy'] === 'same-origin', 'successful clean form page uses same-origin referrer policy');
}
foreach ([$callback, $missingBrowser, $deniedCallback, $unexpectedCallback, $complete, $mfaPage, $preview, $handoff, $mfa, $malformed, $metadata] as $privateResponse) {
    check($privateResponse['headers']['Referrer-Policy'] === 'no-referrer', 'callback completion error and native artifact responses suppress referrer');
}
$nullOrigin = $postServer; $nullOrigin['HTTP_ORIGIN'] = 'null';
check($web->handle($nullOrigin, ['action' => 'setup'], ['csrf' => $adminCsrf], $cookies)['status'] === 403, 'null Origin remains denied even with valid CSRF');

$app->callbackUrl = 'https://crm.example.test' . Config::ENTRY . '?action=callback';
$app->backchannelLogoutUrl = 'https://crm.example.test' . Config::ENTRY . '?action=backchannel-logout';
$configuredPage = $web->handle($server, [], [], $cookies);
check(has($configuredPage['body'], 'id="oidc-callback" type="text" readonly value="' . $app->callbackUrl . '"'), 'settings display exact configured login redirect URI');
check(has($configuredPage['body'], 'id="oidc-backchannel-logout" type="text" readonly value="' . $app->backchannelLogoutUrl . '"'), 'settings display exact configured server logout URL');
check(has($configuredPage['body'], 'provider must be able to reach it over HTTPS') && has($configuredPage['body'], 'native password sessions are unaffected'), 'provider registration explains reachability and native session scope');
$app->backchannelLogoutUrl = 'https://example.test/" autofocus onfocus="unsafe';
$escapedPage = $web->handle($server, [], [], $cookies);
check(!has($escapedPage['body'], 'value="https://example.test/" autofocus') && has($escapedPage['body'], '&quot; autofocus'), 'logout URL is escaped at output boundary');
$app->backchannelLogoutUrl = null;
check(!has($web->handle($server, [], [], $cookies)['body'], 'id="oidc-backchannel-logout"'), 'unconfigured logout URL does not block initial setup');

$logoutServer = $postServer;
unset($logoutServer['HTTP_ORIGIN']);
$logout = fn(string $body, array $overrides = [], array $query = ['action' => 'backchannel-logout'], array $requestCookies = []) =>
    $web->handle(array_replace($logoutServer, $overrides), $query, [], $requestCookies, $body);
$app->session->authorized = false;
$app->fresh = false;
$app->ready = false;
$nativeChecks = [$app->session->adminChecks, $app->session->currentChecks];
$logoutResponse = $logout('logout_token=synthetic.signed.token');
check($logoutResponse['status'] === 200 && $logoutResponse['body'] === '', 'logout acknowledgement is empty HTTP200 after core success');
check(!$logoutResponse['cookies'] && !isset($logoutResponse['headers']['Location']) && !isset($logoutResponse['headers']['x-auth-token']), 'logout never issues a browser session artifact or redirect');
check($logoutResponse['headers']['Cache-Control'] === 'no-store, max-age=0' && $logoutResponse['headers']['Referrer-Policy'] === 'no-referrer', 'logout response is private and uncacheable');
check([$app->session->adminChecks, $app->session->currentChecks] === $nativeChecks, 'server logout requires no native browser or administrator context');
check(end($app->calls)[0] === 'backchannel-logout' && end($app->calls)[1] === ['logoutToken' => 'synthetic.signed.token', 'audit' => ['remoteAddress' => '192.0.2.229', 'userAgent' => 'unit']], 'only raw form token and trusted audit reach core');
check($logout('logout_token=synthetic.signed.token', ['HTTP_ORIGIN' => 'https://provider.example.test'], ['action' => 'backchannel-logout'], ['nms-session' => ['malformed'], Web::BROWSER_COOKIE => 'invalid'])['status'] === 200, 'provider logout ignores browser Origin and cookies without requiring enabled login');
check($logout('extension=one&logout_token=synthetic.signed.token&extension=two&future%5B0%5D=value')['status'] === 200, 'bounded unknown protocol form values are ignored');
check($logout('logout%5Ftoken=synthetic.signed.token', ['CONTENT_TYPE' => 'application/x-www-form-urlencoded; charset=UTF-8'])['status'] === 200, 'standard form key encoding and charset are accepted');
$beforeLogout = count($app->calls);
$invalidLogout = [
    '', 'logout_token=', 'extension=value', 'logout_token=one&logout_token=two',
    'logout_token=one&logout%5Ftoken=two', 'logout_token%5B%5D=one',
    'logout_token=one&logout_token%5Bignored%5D=two', 'logout.token=one',
    'logout_token=bad%ZZ', 'logout_token=bad%00token', 'logout_token=bad%FFtoken',
    'logout_token=' . str_repeat('a', 32769),
    'logout_token=a&' . implode('&', array_fill(0, 24, 'extension=ok')),
    'logout_token=a&' . str_repeat('x', 65536),
];
foreach ($invalidLogout as $index => $body) {
    $rejected = $logout($body);
    check($rejected['status'] === 400 && $rejected['body'] === '{"error":"invalid_request"}' && !$rejected['cookies'], 'malformed logout form denied without reflection case ' . $index);
}
check(count($app->calls) === $beforeLogout, 'invalid logout forms never reach token validation or native cleanup');
foreach (['GET', 'PUT', 'DELETE', 'HEAD'] as $method) { check($logout('logout_token=a', ['REQUEST_METHOD' => $method])['status'] === 400, 'logout rejects non-POST method ' . $method); }
check($logout('logout_token=a', ['CONTENT_TYPE' => 'application/json'])['status'] === 400, 'logout rejects unsupported media type');
check($logout('logout_token=a', ['CONTENT_LENGTH' => '65537'])['status'] === 400, 'logout rejects oversized declared body');
check($logout('logout_token=a', [], ['action' => 'backchannel-logout', 'logout_token' => 'query-token'])['status'] === 400, 'query cannot supply or supplement logout token');
check($web->handle($logoutServer, ['action' => 'backchannel-logout'], ['logout_token' => 'parsed-token'], [])['status'] === 400, 'raw logout form is required despite a parsed POST token');
check($logout('extension=ignored', ['HTTP_LOGOUT_TOKEN' => 'header-token'], ['action' => 'backchannel-logout'], ['logout_token' => 'cookie-token'])['status'] === 400, 'headers and cookies cannot supply logout token');
check($logout('logout_token=' . str_repeat('a', 32768))['status'] === 200, 'logout transport accepts exact token byte limit for core validation');
$prefix = 'logout_token=a&extension=' . str_repeat('b', 32768) . '&other=';
check($logout($prefix . str_repeat('c', 65536 - strlen($prefix)))['status'] === 200, 'logout transport accepts exact total body byte limit');
$app->logoutVm = ['ok' => false, 'pending' => true];
check($logout('logout_token=a')['status'] === 503, 'unexpected core acknowledgement never reports logout success');
$app->logoutVm = ['ok' => true];
foreach (['LOGOUT_INVALID', 'LOGOUT_PENDING'] as $code) {
    $app->failure = new AppException($code, 400);
    $failedLogout = $logout('logout_token=PRIVATE_LOGOUT_TOKEN');
    check($failedLogout['status'] === 400 && $failedLogout['body'] === '{"error":"invalid_request"}', 'core logout rejection uses fixed response ' . $code);
}
foreach ([new AppException('STATE_UNAVAILABLE', 503), new \RuntimeException('PRIVATE_PROVIDER_RESPONSE')] as $error) {
    $app->failure = $error;
    $failedLogout = $logout('logout_token=PRIVATE_LOGOUT_TOKEN');
    check($failedLogout['status'] === 503 && $failedLogout['body'] === '{"error":"temporarily_unavailable"}' && !$failedLogout['cookies'], 'logout infrastructure failure remains private and retryable');
}
$app->failure = null;
$app->session->authorized = true;
$app->fresh = true;
$app->ready = true;
check($web->handle($logoutServer, ['action' => 'setup'], ['csrf' => $adminCsrf], $cookies)['status'] === 403, 'logout exception does not weaken admin Origin requirement');
check($web->handle($logoutServer, ['action' => 'handoff'], ['csrf' => $flowCsrf, 'flow' => $flow], $cookies)['status'] === 403, 'logout exception does not weaken native handoff Origin requirement');
check($web->handle($postServer, ['action' => 'setup'], [], $cookies)['status'] === 403, 'logout exception does not weaken admin CSRF requirement');

foreach (['PROVIDER_LOGGED_OUT' => [403, 'provider session was signed out'], 'LEGACY_CLEANUP_PENDING' => [503, 'cleanup of earlier OpenID Connect sessions']] as $code => [$status, $message]) {
    $app->failure = new AppException($code, $status);
    $logoutFence = $web->handle($server, ['action' => 'callback', 'code' => 'PRIVATE_AUTHORIZATION_CODE'], [], $cookies);
    check($logoutFence['status'] === 303 && $logoutFence['headers']['Location'] === Config::ENTRY . '?action=error&reason=' . $code && $logoutFence['body'] === '', 'logout fence removes authorization code before clean error ' . $code);
    $cleanError = $web->handle($server, ['action' => 'error', 'reason' => $code], [], []);
    check($cleanError['status'] === $status && has($cleanError['body'], $message) && $cleanError['headers']['Referrer-Policy'] === 'no-referrer', 'logout fence displays actionable private error ' . $code);
}
$app->failure = null;
$app->legacyCleanupPending = true;
check(has($web->handle($server, [], [], $cookies)['body'], 'New OpenID Connect sign-ins resume after cleanup completes.'), 'native Settings explains pending legacy session cleanup');
$app->legacyCleanupPending = false;
check(!has($web->handle($server, [], [], $cookies)['body'], 'New OpenID Connect sign-ins resume after cleanup completes.'), 'legacy cleanup notice clears when core reports completion');

echo json_encode(['suite' => 'web-boundary', 'passed' => $passed, 'failed' => 0], JSON_THROW_ON_ERROR) . "\n";
