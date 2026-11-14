<?php
declare(strict_types=1);
namespace UcrmOidc;

/** HTTP boundary. Only Application may create transactions or native sessions. */
final class Web
{
    public const BROWSER_COOKIE = '__Host-ucrm-oidc-browser';
    public const LOGOUT_BODY_LIMIT = 65536;
    private const LOGOUT_TOKEN_LIMIT = 32768;
    private const ASSETS = '/crm/_plugins/ucrm-oidc/public/';
    private const COOKIE_PATH = '/';
    private const CALLBACK_ERRORS = [
        'REQUEST_FAILED', 'ADMISSION_DENIED', 'VERIFIED_EMAIL_REQUIRED', 'BINDING_CONFLICT',
        'IDENTITY_UNLINKED', 'IDENTITY_CHANGED', 'FLOW_EXPIRED', 'FLOW_INVALID', 'FLOW_USED',
        'FLOW_CONFIGURATION_CHANGED', 'CONFIG_CHANGED', 'BINDING_CHANGED', 'PROVIDER_UNAVAILABLE',
        'AUTHENTICATION_DENIED', 'ISSUER_MISMATCH', 'SUBJECT_MISMATCH', 'INVALID_JWKS',
        'NATIVE_UNAVAILABLE', 'STATE_UNAVAILABLE', 'OIDC_DISABLED', 'RATE_LIMITED',
        'BROWSER_BINDING_REQUIRED', 'ENDPOINT_ORIGIN_DENIED', 'SETUP_REQUIRED',
        'PROVIDER_LOGGED_OUT', 'LEGACY_CLEANUP_PENDING',
    ];
    private array $responseCookies = [];

    public function __construct(private readonly Application $app, private readonly int $pluginId = 0) {}

    /** Response DTO keeps emission separate so tests exercise the actual route boundary. */
    public function handle(array $server, array $query, array $post, array $cookies, ?string $rawBody = null): array
    {
        $this->responseCookies = [];
        $action = is_string($query['action'] ?? null) ? $query['action'] : 'admin';
        try {
            $this->bounded($query, 16, 8192);
            $this->uniqueQuery($server);
            // The provider authenticates this one server-to-server route with a
            // signed Logout Token. Browser session, Origin and CSRF checks below
            // remain mandatory for every ordinary browser POST.
            if ($action === 'backchannel-logout') { return $this->backchannelLogout($server, $query, $rawBody); }
            $this->bounded($post, 24, 16384);
            if ((int) ($server['CONTENT_LENGTH'] ?? 0) > 32768) { throw new AppException('REQUEST_TOO_LARGE', 413); }
            $method = $server['REQUEST_METHOD'] ?? 'GET';
            $gets = ['admin', 'status', 'start', 'callback', 'complete', 'bindings', 'audit', 'error'];
            $posts = ['start', 'handoff', 'mfa-complete', 'settings', 'secret-replace', 'secret-clear', 'test', 'setup', 'lookup', 'unlink', 'relink'];
            if (!in_array($action, array_unique([...$gets, ...$posts]), true)) { throw new AppException('NOT_FOUND', 404); }
            if (($method !== 'GET' || !in_array($action, $gets, true)) && ($method !== 'POST' || !in_array($action, $posts, true))) {
                throw new AppException('METHOD_NOT_ALLOWED', 405);
            }
            // Even initial setup is HTTPS-only. This is the serving origin, not the provider setting.
            $origin = $this->app->native()->servingOrigin($server);
            if ($method === 'POST') {
                if (($server['HTTP_ORIGIN'] ?? null) !== $origin) { throw new AppException('ORIGIN_DENIED', 403); }
                $contentType = strtolower(trim(explode(';', (string) ($server['CONTENT_TYPE'] ?? ''))[0]));
                if ($contentType !== 'application/x-www-form-urlencoded') { throw new AppException('CONTENT_TYPE_DENIED', 415); }
            }
            if ($action === 'error') {
                Config::keys($query, ['action', 'reason']);
                $reason = $query['reason'] ?? 'REQUEST_FAILED';
                if (!in_array($reason, self::CALLBACK_ERRORS, true)) { throw new AppException('BAD_REQUEST'); }
                $status = match ($reason) {
                    'PROVIDER_UNAVAILABLE' => 502,
                    'NATIVE_UNAVAILABLE', 'STATE_UNAVAILABLE', 'SETUP_REQUIRED', 'LEGACY_CLEANUP_PENDING' => 503,
                    'RATE_LIMITED' => 429,
                    'BINDING_CONFLICT', 'FLOW_USED', 'FLOW_CONFIGURATION_CHANGED', 'CONFIG_CHANGED', 'BINDING_CHANGED' => 409,
                    'REQUEST_FAILED' => 400,
                    default => 403,
                };
                throw new AppException($reason, $status);
            }
            if ($action === 'status') {
                Config::keys($query, ['action']);
                $vm = $this->app->status();
                return $this->json(['enabled' => ($vm['enabled'] ?? false) === true, 'ready' => ($vm['ready'] ?? false) === true,
                    'loginLabel' => $this->text($vm['loginLabel'] ?? 'Sign in with OpenID Connect', 320),
                    'startPath' => Config::ENTRY . '?action=start']);
            }
            if ($action === 'start') { return $this->start($method, $server, $query, $post, $cookies); }
            if ($action === 'callback') {
                Config::keys($query, ['action', 'state', 'code', 'iss', 'error', 'error_description', 'error_uri', 'session_state']);
                $parameters = $query;
                unset($parameters['action']);
                $result = $this->app->callback($this->browser($cookies, false), $parameters, $this->app->native()->audit($server));
                return $this->redirect(Config::ENTRY . '?action=complete&flow=' . $this->flow($result['flowId'] ?? null));
            }
            if (in_array($action, ['complete', 'handoff', 'mfa-complete'], true)) {
                return $this->completion($action, $server, $query, $post, $cookies);
            }
            return $this->admin($action, $method, $server, $query, $post, $cookies);
        } catch (\Throwable $error) {
            if ($action === 'backchannel-logout') {
                $temporary = !($error instanceof AppException) || $error->httpStatus >= 500;
                return $this->json(['error' => $temporary ? 'temporarily_unavailable' : 'invalid_request'], $temporary ? 503 : 400);
            }
            $known = $error instanceof AppException || $error instanceof NativeSessionException;
            $code = $known && preg_match('/\A[A-Z][A-Z0-9_]{0,63}\z/D', $error->safeCode) ? $error->safeCode : 'REQUEST_FAILED';
            if ($action === 'callback') {
                // Failed callbacks must lose their authorization code/state too.
                // Only these fixed symbolic reasons cross the clean redirect.
                $reason = in_array($code, self::CALLBACK_ERRORS, true) ? $code : 'REQUEST_FAILED';
                return $this->redirect(Config::ENTRY . '?action=error&reason=' . $reason);
            }
            $status = $error instanceof AppException ? $error->httpStatus : ($code === 'ADMISSION_DENIED' ? 403 : 503);
            if ($status < 400 || $status > 599) { $status = 500; }
            if (in_array($action, ['status', 'handoff', 'mfa-complete'], true)) {
                return $this->json(['ok' => false, 'error' => ['code' => $code]], $status);
            }
            $message = match ($code) {
                'ADMISSION_DENIED' => in_array($action, ['admin', 'bindings', 'audit', 'settings', 'secret-replace', 'secret-clear', 'test', 'setup', 'lookup', 'unlink', 'relink'], true)
                    ? 'Sign in with a native CRM account that can edit plugins to open these settings.'
                    : 'This sign-in does not match an eligible, pre-created native staff account. Contact your administrator.',
                'VERIFIED_EMAIL_REQUIRED' => 'Your identity provider must supply a verified email address that matches your existing native staff account. Contact your administrator.',
                'BINDING_CONFLICT' => 'This identity or native account already has a different account link. Ask an administrator to review the link.',
                'IDENTITY_UNLINKED' => 'This external account link has been disabled. Contact your administrator or use native password login.',
                'FLOW_EXPIRED', 'CONFIG_CHANGED', 'FLOW_CONFIGURATION_CHANGED', 'BINDING_CHANGED' => 'This sign-in expired or its configuration changed. Start a new sign-in.',
                'PROVIDER_UNAVAILABLE' => 'The identity provider could not be reached. Try again later or use native password login.',
                'PROVIDER_LOGGED_OUT' => 'Your provider session was signed out. Start a new sign-in.',
                'LEGACY_CLEANUP_PENDING' => 'An upgrade is finishing cleanup of earlier OpenID Connect sessions. Try again after cleanup completes or use native password login.',
                'OIDC_DISABLED' => 'New OpenID Connect sign-ins are disabled. Identity preview also requires this switch. An administrator can temporarily enable sign-in in the native plugin Settings page, run the protected preview, and disable sign-in again if rollout is not ready. Ordinary OIDC login is available during that window.',
                'OIDC_NOT_READY' => 'OpenID Connect is not ready. Check the saved provider settings, required client secret and any pending cleanup on the plugin Settings page.',
                'RECENT_AUTH_REQUIRED', 'FRESH_AUTH_REQUIRED', 'RECENT_AUTHENTICATION_REQUIRED' => 'Use the native account menu to sign out, then sign back in and reopen plugin settings. Opening the login page while already signed in does not refresh authentication. Save within five minutes of signing in.',
                'ORIGIN_DENIED', 'CSRF_DENIED', 'CSRF_INVALID', 'INVALID_CSRF' => 'This request could not be verified. Reopen the page and try again.',
                default => 'The request could not be completed. Reopen the page or use the native login to recover.',
            };
            return $this->page('Request not completed', '<p role="alert">' . self::e($message) . '</p><p class="oidc-muted">Code: ' . self::e($code) . '</p>' . $this->recovery(in_array($code, ['RECENT_AUTH_REQUIRED', 'FRESH_AUTH_REQUIRED', 'RECENT_AUTHENTICATION_REQUIRED'], true)), $status);
        }
    }

    private function backchannelLogout(array $server, array $query, ?string $rawBody): array
    {
        Config::keys($query, ['action']);
        $contentType = strtolower(trim(explode(';', (string) ($server['CONTENT_TYPE'] ?? ''))[0]));
        if (($server['REQUEST_METHOD'] ?? '') !== 'POST' || $contentType !== 'application/x-www-form-urlencoded'
            || (int) ($server['CONTENT_LENGTH'] ?? 0) > self::LOGOUT_BODY_LIMIT
            || $rawBody === null || strlen($rawBody) > self::LOGOUT_BODY_LIMIT) {
            throw new AppException('LOGOUT_INVALID', 400);
        }
        // Parse the bounded raw form ourselves: PHP's $_POST silently collapses
        // duplicate names and normalizes dots/spaces in names. Neither may select
        // a different signed token. Unknown extension fields are ignored (§2.5).
        $parts = explode('&', $rawBody);
        if (count($parts) > 24) { throw new AppException('LOGOUT_INVALID', 400); }
        $token = null;
        foreach ($parts as $part) {
            if ($part === '') { continue; }
            if (preg_match('/%(?![0-9A-Fa-f]{2})/', $part)) { throw new AppException('LOGOUT_INVALID', 400); }
            [$encodedKey, $encodedValue] = array_pad(explode('=', $part, 2), 2, '');
            $key = urldecode($encodedKey);
            $value = urldecode($encodedValue);
            if (strlen($key) > 64 || strlen($value) > self::LOGOUT_TOKEN_LIMIT
                || str_contains($key, "\0") || str_contains($value, "\0")
                || !mb_check_encoding($key, 'UTF-8') || !mb_check_encoding($value, 'UTF-8')) {
                throw new AppException('LOGOUT_INVALID', 400);
            }
            if (str_starts_with($key, 'logout_token[')) { throw new AppException('LOGOUT_INVALID', 400); }
            if ($key !== 'logout_token') { continue; }
            if ($token !== null || $value === '') { throw new AppException('LOGOUT_INVALID', 400); }
            $token = $value;
        }
        if ($token === null) { throw new AppException('LOGOUT_INVALID', 400); }
        $this->app->native()->servingOrigin($server);
        $result = $this->app->backchannelLogout($token, $this->app->native()->audit($server));
        if (($result['ok'] ?? null) !== true) { throw new AppException('STATE_UNAVAILABLE', 503); }
        return $this->response(200, ['Content-Type' => 'text/plain; charset=UTF-8'], '');
    }

    private function start(string $method, array $server, array $query, array $post, array $cookies): array
    {
        Config::keys($query, ['action', 'return', 'preview', 'fresh']);
        Config::keys($post, ['csrf', 'return', 'preview', 'fresh']);
        $input = $method === 'POST' ? $post : $query;
        $return = Config::returnPath($this->text($input['return'] ?? '/crm/', 2048));
        $preview = $this->flag($input['preview'] ?? '0');
        $fresh = $this->flag($input['fresh'] ?? '0');
        $context = $preview ? $this->app->native()->adminContext($cookies, $server) : null;
        $browser = $this->browser($cookies, $method === 'GET');
        $status = $this->app->status();
        if (($status['enabled'] ?? false) !== true) { throw new AppException('OIDC_DISABLED', 403); }
        if (($status['ready'] ?? false) !== true) { throw new AppException('OIDC_NOT_READY', 503); }
        if ($method === 'POST') {
            $this->app->checkCsrf($browser, 'flow:start', $this->text($post['csrf'] ?? '', 256));
            $result = $this->app->start($browser, $return, $this->app->native()->audit($server), $context, $fresh);
            $url = $this->text($result['authorizationUrl'] ?? '', 8192);
            Config::url($url);
            $origin = Config::origin($url);
            if (!in_array($origin, $this->app->authorizationOrigins(), true)) { throw new AppException('ENDPOINT_ORIGIN_DENIED', 403); }
            // Complete the same-origin form navigation before leaving for the
            // provider. A 303 here carries form-action into its federated redirects.
            $restart = Config::ENTRY . '?' . http_build_query(['action' => 'start', 'return' => $return, 'preview' => $preview ? '1' : '0', 'fresh' => $fresh ? '1' : '0']);
            $body = '<p id="oidc-provider-progress" role="status">Opening your identity provider. If the page does not open, choose Continue to provider below.</p><p><a id="oidc-provider-continue" rel="noreferrer" data-provider-origin="' . self::e($origin) . '" href="' . self::e($url) . '">Continue to provider</a></p><noscript><p>JavaScript is disabled. Use Continue to provider to open sign-in.</p></noscript><p>If authentication is blocked or cannot finish, <a href="' . self::e($restart) . '">start again</a> or use native password login. Contact your administrator if the problem continues.</p>' . $this->recovery()
                . '<script defer src="' . self::ASSETS . 'provider-transition.js"></script>';
            return $this->page('Continue to your identity provider', $body);
        }
        $csrf = $this->app->csrf($browser, 'flow:start');
        $label = $preview ? 'Preview provider identity' : $this->text($status['loginLabel'] ?? 'Sign in with OpenID Connect', 320);
        $body = '<p>' . ($preview ? 'Verify the provider identity and see the existing native account it matches. This preview does not sign in or change account links.' : 'Continue to your identity provider. Your existing native account and permissions will be used.') . '</p>';
        if ($fresh) { $body .= '<p>A fresh provider sign-in is required for this request.</p>'; }
        $body .= $this->form('start', $csrf, ['return' => $return, 'preview' => $preview ? '1' : '0', 'fresh' => $fresh ? '1' : '0'], '<button class="button button--primary" type="submit">' . self::e($label) . '</button>') . $this->recovery();
        return $this->page($label, $body, 200, true);
    }

    private function completion(string $action, array $server, array $query, array $post, array $cookies): array
    {
        Config::keys($query, ['action', 'flow']);
        Config::keys($post, $action === 'mfa-complete' ? ['csrf', 'flow', 'otp'] : ['csrf', 'flow']);
        $flow = $this->flow($action === 'complete' ? ($query['flow'] ?? null) : ($post['flow'] ?? null));
        $browser = $this->browser($cookies, false);
        if ($action === 'complete') {
            $vm = $this->app->completion($browser, $flow);
            if (($vm['kind'] ?? '') === 'preview') {
                $context = $this->app->native()->adminContext($cookies, $server);
                if (!is_string($vm['previewRequiresAdminId'] ?? null) || !hash_equals($context['nativeUserId'], $vm['previewRequiresAdminId'])) {
                    throw new AppException('ADMISSION_DENIED', 403);
                }
                $preview = $vm['preview'] ?? [];
                $rows = '';
                foreach (['issuer' => 'Issuer', 'subject' => 'Subject', 'email' => 'Verified email', 'username' => 'Native username', 'role' => 'NMS role', 'ucrmRole' => 'CRM role'] as $key => $label) {
                    $rows .= '<dt>' . self::e($label) . '</dt><dd>' . self::e(is_string($preview[$key] ?? null) ? $preview[$key] : '—') . '</dd>';
                }
                $rows .= '<dt>Email verified</dt><dd>' . (($preview['emailVerified'] ?? false) === true ? 'Yes' : 'No') . '</dd><dt>Existing link</dt><dd>' . (($preview['alreadyLinked'] ?? false) === true ? 'Yes' : 'No') . '</dd>';
                return $this->page('Provider identity preview', '<dl class="oidc-details">' . $rows . '</dl><p>Existing native permissions are retained.</p><p>No login session or new account link was created.</p>' . $this->recovery());
            }
            if (!in_array($vm['kind'] ?? null, ['session', 'mfa'], true)) { throw new AppException('INVALID_FLOW'); }
            $csrf = $this->app->csrf($browser, 'flow:' . $flow);
            $isMfa = $vm['kind'] === 'mfa';
            $handoff = $this->form('handoff', $csrf, ['flow' => $flow], '<button class="button button--primary" type="submit">Continue signing in</button>', 'id="oidc-handoff"' . ($isMfa ? ' hidden' : ''));
            $mfa = $this->form('mfa-complete', $csrf, ['flow' => $flow], '<label for="oidc-otp">Native authenticator code</label><input id="oidc-otp" name="otp" type="text" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" minlength="6" maxlength="6" required><button class="button button--primary" type="submit">Verify and sign in</button>', 'id="oidc-mfa"' . ($isMfa ? '' : ' hidden'));
            return $this->page('Complete sign-in', '<p>Your provider identity has been verified. Continue with your existing native account.</p><div id="oidc-signin">' . $handoff . $mfa . '<p id="oidc-progress" role="status" aria-live="polite"></p></div>' . $this->recovery());
        }
        $this->app->checkCsrf($browser, 'flow:' . $flow, $this->text($post['csrf'] ?? '', 256));
        $audit = $this->app->native()->audit($server);
        $current = $this->app->native()->current($cookies, $server);
        if ($action === 'mfa-complete') {
            $otp = $this->text($post['otp'] ?? '', 6);
            if (!preg_match('/\A[0-9]{6}\z/D', $otp)) { throw new AppException('MFA_INVALID'); }
            $result = $this->app->completeMfa($browser, $flow, $otp, $audit, $current);
        } else {
            $result = $this->app->handoff($browser, $flow, $audit, $current);
        }
        if (($result['kind'] ?? '') === 'mfa') { return $this->json(['ok' => true, 'kind' => 'mfa']); }
        if (($result['kind'] ?? '') !== 'session' || !$this->uuid($result['token'] ?? null) || !$this->uuid($result['ucrmSessionId'] ?? null)) {
            throw new AppException('NATIVE_UNAVAILABLE', 503);
        }
        if (!array_key_exists('cookieTtlMs', $result)) { throw new AppException('NATIVE_UNAVAILABLE', 503); }
        $ttl = $result['cookieTtlMs'];
        if ($ttl !== null && (!is_int($ttl) || $ttl <= 0)) { throw new AppException('NATIVE_UNAVAILABLE', 503); }
        $returnPath = Config::returnPath($result['returnPath']);
        $this->responseCookies[] = ['name' => 'nms-session', 'value' => $result['ucrmSessionId'], 'options' => [
            'expires' => $ttl === null ? 0 : time() + (int) ceil($ttl / 1000), 'path' => '/', 'secure' => true, 'httponly' => true, 'samesite' => 'Lax',
        ]];
        return $this->json(['ok' => true, 'kind' => 'session', 'returnPath' => $returnPath], 200, ['x-auth-token' => $result['token']]);
    }

    private function admin(string $action, string $method, array $server, array $query, array $post, array $cookies): array
    {
        Config::keys($query, ['action', 'page', 'search']);
        $context = $this->app->native()->adminContext($cookies, $server);
        $csrf = $this->app->csrf($context['sessionId'], 'admin');
        $notice = '';
        $extra = '';
        if ($method === 'POST') {
            $this->app->checkCsrf($context['sessionId'], 'admin', $this->text($post['csrf'] ?? '', 256));
            unset($post['csrf']);
            if (in_array($action, ['settings', 'secret-replace', 'secret-clear', 'unlink', 'relink'], true)) {
                try { $this->app->assertFresh($context); }
                catch (AppException $error) {
                    if ($error->safeCode !== 'RECENT_AUTH_REQUIRED') { throw $error; }
                    $vm = $this->app->configuration($context);
                    // Retain only declared, non-secret provider fields after authenticated
                    // Origin/CSRF checks. Credentials and account-link operations are never replayed.
                    if ($action === 'settings') {
                        foreach (Config::DEFAULTS as $key => $_) {
                            if (isset($post[$key])) { $vm['settings'][$key] = $key === 'endpointOrigins' ? explode("\n", str_replace("\r", '', $post[$key])) : $post[$key]; }
                        }
                        if (isset($post['expectedProviderRevision'])) { $vm['providerRevision'] = $this->integer($post['expectedProviderRevision']); }
                    }
                    $body = $this->navigation() . '<section class="oidc-card"><h2>Fresh native sign-in required</h2><p role="alert">Sign out using the native account menu, then sign back in with your native credentials. Opening the login page while already signed in does not refresh authentication. No session is signed out automatically.</p><ol><li><a href="/nms/" target="_blank" rel="noopener noreferrer">Open the native account menu in a new tab</a>, choose Sign Out, then sign in again.</li><li>Return to this tab and <a href="' . Config::ENTRY . '">reload provider settings</a>.</li><li>Review and save within five minutes. Re-enter any client secret; secrets are never retained.</li></ol><p>Unsaved provider fields are shown below. When browser storage is available, this tab retains only those non-secret fields for 15 minutes and restores them after reload for the same administrator and unchanged settings revision.</p><p class="oidc-muted">Code: RECENT_AUTH_REQUIRED</p></section>';
                    return $this->page('Sign in again', $body . $this->settings($vm, $csrf, $context, $action === 'settings' ? 'recovery' : 'editing'), 403, true);
                }
            }
            switch ($action) {
                case 'settings':
                    Config::keys($post, array_merge(array_keys(Config::DEFAULTS), ['expectedProviderRevision']));
                    $post['expectedProviderRevision'] = $this->integer($post['expectedProviderRevision'] ?? null);
                    $post['maxAge'] = ($post['maxAge'] ?? '') === '' ? null : $this->integer($post['maxAge']);
                    $post['endpointOrigins'] = array_values(array_filter(array_map('trim', explode("\n", str_replace("\r", '', $post['endpointOrigins'] ?? ''))), static fn(string $v): bool => $v !== ''));
                    $this->app->saveSettings($context, $post);
                    $notice = 'Provider settings saved.';
                    break;
                case 'secret-replace':
                case 'secret-clear':
                    Config::keys($post, $action === 'secret-replace' ? ['expectedCredentialRevision', 'clientSecret'] : ['expectedCredentialRevision']);
                    $post['expectedCredentialRevision'] = $this->integer($post['expectedCredentialRevision'] ?? null);
                    if ($action === 'secret-replace') { $this->app->replaceSecret($context, $post); $notice = 'Credential update completed. A blank value preserves the saved secret.'; }
                    else { $this->app->clearSecret($context, $post); $notice = 'Saved client secret cleared.'; }
                    break;
                case 'test':
                    Config::keys($post, []);
                    $this->app->connectionTest($context);
                    $notice = 'Provider discovery and connection checks passed. This does not verify client credentials, account matching, native session issuance or logout. Identity preview checks provider authentication and account matching separately.';
                    break;
                case 'setup':
                    Config::keys($post, []);
                    $this->app->setup($context);
                    $notice = 'Plugin setup checks completed.';
                    break;
                case 'lookup':
                    Config::keys($post, ['email', 'bindingId', 'expectedVersion']);
                    $found = $this->app->accountLookup($context, $this->text($post['email'] ?? '', 320));
                    $extra = '<section class="oidc-card"><h2>Confirm account link</h2><p>Use the existing native account <strong>' . self::e($found['username']) . '</strong> (' . self::e($found['email']) . '). Existing native permissions are retained.</p>'
                        . $this->form('relink', $csrf, ['bindingId' => $this->text($post['bindingId'] ?? '', 128), 'expectedVersion' => (string) $this->integer($post['expectedVersion'] ?? null), 'nativeUserId' => $found['nativeUserId']], '<button class="button button--primary" type="submit">Confirm relink</button>') . '</section>';
                    break;
                case 'unlink':
                case 'relink':
                    Config::keys($post, $action === 'unlink' ? ['bindingId', 'expectedVersion'] : ['bindingId', 'expectedVersion', 'nativeUserId']);
                    $post['expectedVersion'] = $this->integer($post['expectedVersion'] ?? null);
                    if ($action === 'unlink') {
                        $result = $this->app->unlink($context, $post);
                        $notice = ($result['pendingCleanup'] ?? 0) > 0
                            ? 'Account link disabled. Some native session cleanup is still pending and will be retried by maintenance.'
                            : 'Account link disabled. Cleanup of its retained plugin-issued native sessions is complete.';
                    }
                    else { $this->app->relink($context, $post); $notice = 'Account link updated.'; }
                    break;
            }
        }
        if (in_array($action, ['bindings', 'audit'], true)) {
            $pagination = ['page' => $this->integer($query['page'] ?? '1', 1), 'search' => $this->text($query['search'] ?? '', 128)];
            return $this->page($action === 'bindings' ? 'Account links' : 'Authentication audit', $this->navigation() . $this->records($action, $this->app->records($context, $action, $pagination), $csrf, $pagination), 200, true);
        }
        $vm = $this->app->configuration($context);
        $vm['discoveryTestPassed'] = $method === 'POST' && $action === 'test';
        return $this->page('OpenID Connect', $this->navigation() . ($notice === '' ? '' : '<p class="oidc-notice" role="status">' . self::e($notice) . '</p>') . $extra . $this->settings($vm, $csrf, $context, $action === 'settings' ? 'saved' : 'editing'), 200, true);
    }

    private function settings(array $vm, string $csrf, array $context, string $draftState): string
    {
        $settings = array_replace(Config::DEFAULTS, $vm['settings']);
        $native = $vm['native'];
        $body = '<section class="oidc-card"><h2>Readiness</h2><dl class="oidc-details"><dt>Native plugin</dt><dd>' . (($native['pluginEnabled'] ?? false) ? 'Enabled' : 'Disabled') . '</dd><dt>OpenID Connect login</dt><dd>' . (($native['enabled'] ?? false) ? 'Enabled' : 'Disabled') . '</dd><dt>Provider configuration</dt><dd>' . (($vm['providerConfigured'] ?? false) ? 'Configured' : 'Needs setup') . '</dd></dl><p>Configured means the provider settings and any required secret are saved. Test provider connection checks discovery separately; it does not prove credentials, account matching, native login or logout. Login availability and pending cleanup are separate from configuration completeness.</p>';
        $body .= '<p>Discovery check: ' . (($vm['discoveryTestPassed'] ?? false) ? 'Passed in this request.' : 'Not checked in this page view. Use Test provider connection; earlier results are available in Audit.') . '</p>';
        if (($vm['legacyCleanupPending'] ?? false) === true) {
            $body .= '<p class="oidc-notice" role="status">An upgrade is finishing cleanup of sessions created by an earlier plugin version. New OpenID Connect sign-ins resume after cleanup completes. Native password login remains available.</p>';
        }
        if ($this->pluginId > 0) { $body .= '<p><a target="_top" href="/crm/system/plugins/' . $this->pluginId . '/configuration">Open native plugin configuration to enable or disable OpenID Connect</a></p>'; }
        $body .= '<p>Accounts must already exist in UCRM/UISP with a unique verified email match. Native roles, permissions, MFA and session lifetimes remain in control.</p>';
        if (is_string($vm['callbackUrl'] ?? null)) { $body .= '<label for="oidc-callback">Login redirect URI to register with your provider</label><input id="oidc-callback" type="text" readonly value="' . self::e($vm['callbackUrl']) . '">'; }
        if (is_string($vm['backchannelLogoutUrl'] ?? null)) {
            $body .= '<label for="oidc-backchannel-logout">Back-channel logout URL to register with your provider</label><input id="oidc-backchannel-logout" type="text" readonly value="' . self::e($vm['backchannelLogoutUrl']) . '"><p class="oidc-muted">Register this URL in your provider\'s server-to-server back-channel logout setting. The provider must be able to reach it over HTTPS. A verified logout request revokes matching sessions created through this plugin; native password sessions are unaffected.</p>';
        }
        $body .= $this->form('setup', $csrf, [], '<button class="button" type="submit">Check plugin setup</button>') . '</section>';
        $fields = '';
        $labels = ['issuer' => 'Issuer URL', 'discoveryUrl' => 'Discovery URL (blank uses standard discovery)', 'clientId' => 'Client ID', 'canonicalOrigin' => 'Public UCRM origin, including HTTPS port if needed', 'scopes' => 'Scopes', 'loginLabel' => 'Login button label', 'emailClaim' => 'Email claim: literal key or RFC 6901 JSON pointer', 'emailVerifiedClaim' => 'Verified-email claim: literal key or RFC 6901 JSON pointer'];
        foreach ($labels as $key => $label) { $fields .= $this->field($key, $label, (string) $settings[$key], in_array($key, ['issuer', 'discoveryUrl', 'canonicalOrigin'], true) ? 'url' : 'text'); }
        $fields .= $this->select('clientAuthMethod', 'Client authentication', $settings['clientAuthMethod'], ['client_secret_basic' => 'Client secret: HTTP Basic', 'client_secret_post' => 'Client secret: POST body', 'none' => 'Public client (no secret)']);
        $fields .= $this->select('emailSource', 'Verified email source', $settings['emailSource'], ['userinfo' => 'UserInfo endpoint', 'id_token' => 'ID token']);
        $fields .= $this->field('maxAge', 'Maximum provider authentication age in seconds (blank: provider default)', $settings['maxAge'] === null ? '' : (string) $settings['maxAge'], 'number');
        $fields .= '<label for="oidc-endpointOrigins">Additional provider endpoint origins, one HTTPS origin per line</label><textarea id="oidc-endpointOrigins" name="endpointOrigins" rows="3" maxlength="8192">' . self::e(implode("\n", $settings['endpointOrigins'])) . '</textarea><p class="oidc-muted">Only add origins required by your provider. The issuer origin is allowed automatically.</p><button class="button button--primary" type="submit">Save provider settings</button>';
        $draftAttributes = 'data-oidc-provider-settings data-draft-owner="' . hash('sha256', 'provider-draft:' . $context['nativeUserId']) . '" data-draft-state="' . $draftState . '"';
        $body .= '<section class="oidc-card"><h2>Provider settings</h2><p>Changing trust settings, credentials or account links requires a sign-in within the last five minutes. If necessary, sign out and back in through the native account menu. Changing the issuer, client ID or client authentication method clears the saved client secret; save the replacement secret afterwards.</p>' . $this->form('settings', $csrf, ['expectedProviderRevision' => (string) $vm['providerRevision']], $fields, $draftAttributes) . '</section>';
        $body .= '<section class="oidc-card"><h2>Client secret</h2><p>' . (($vm['secretPresent'] ?? false) ? 'A client secret is saved. Its value is never displayed.' : 'No client secret is saved.') . '</p>' . $this->form('secret-replace', $csrf, ['expectedCredentialRevision' => (string) $vm['credentialRevision']], '<label for="oidc-clientSecret">New client secret (blank keeps the saved value)</label><input id="oidc-clientSecret" name="clientSecret" type="password" autocomplete="new-password" maxlength="4096" value=""><button class="button button--primary" type="submit">Save client secret</button>') . $this->form('secret-clear', $csrf, ['expectedCredentialRevision' => (string) $vm['credentialRevision']], '<button class="button" type="submit">Clear saved client secret</button>', 'data-confirm="Clear the saved client secret? Existing native sessions keep their native lifetime."') . '</section>';
        return $body . '<section class="oidc-card"><h2>Test and recovery</h2>' . $this->form('test', $csrf, [], '<button class="button" type="submit">Test provider connection</button>') . '<p>Discovery can be tested with new sign-ins disabled. Identity preview requires temporarily enabling OpenID Connect login in native plugin Settings. Ordinary OIDC login is available during this window. Run the administrator-only preview, then disable sign-in again if rollout is not ready. The provider may also deny access independently.</p><p><a target="_top" href="' . Config::ENTRY . '?action=start&amp;preview=1">Preview verified identity and native account match</a></p><p><a target="_top" href="' . Config::ENTRY . '?action=start&amp;fresh=1">Sign in again with fresh provider authentication</a></p><p>For a fresh native password login, first sign out using the native account menu, then sign back in and return to plugin Settings.</p><p><a target="_blank" rel="noopener noreferrer" href="/nms/">Open native account menu</a></p></section>';
    }

    private function records(string $kind, array $vm, string $csrf, array $query): string
    {
        $body = '<form method="get" action="' . Config::ENTRY . '"><input type="hidden" name="action" value="' . $kind . '"><label for="oidc-search">Filter records</label><input id="oidc-search" name="search" type="search" maxlength="320" value="' . self::e($query['search']) . '"><button class="button" type="submit">Search</button></form><ul class="oidc-records">';
        foreach ($vm['items'] as $item) {
            if ($kind === 'bindings') {
                $body .= '<li class="oidc-card"><h2>' . self::e($item['username']) . '</h2><dl class="oidc-details"><dt>Issuer</dt><dd>' . self::e($item['issuer']) . '</dd><dt>Subject</dt><dd>' . self::e($item['subject']) . '</dd><dt>Status</dt><dd>' . ($item['active'] ? 'Active' : 'Disabled') . '</dd></dl>';
                $hidden = ['bindingId' => (string) $item['id'], 'expectedVersion' => (string) $item['version']];
                if ($item['active']) { $body .= $this->form('unlink', $csrf, $hidden, '<button class="button" type="submit">Disable account link</button>', 'data-confirm="Disable this external account link and request cleanup of its plugin-issued native sessions?"'); }
                $body .= $this->form('lookup', $csrf, $hidden, '<label>Relink to an existing native account by email<input name="email" type="email" maxlength="320" required></label><button class="button" type="submit">Look up account</button>') . '</li>';
            } else {
                $body .= '<li class="oidc-card"><h2>' . self::e((string) $item['event']) . '</h2><dl class="oidc-details">';
                $body .= '<dt>Time (UTC)</dt><dd>' . $this->auditTime($item['at'] ?? null) . '</dd>';
                foreach (['outcome' => 'Outcome', 'actor' => 'Actor reference', 'object' => 'Object reference'] as $key => $label) { $body .= '<dt>' . $label . '</dt><dd>' . self::e((string) ($item[$key] ?? '—')) . '</dd>'; }
                $body .= '</dl></li>';
            }
        }
        $body .= '</ul>';
        if (!$vm['items']) { $body .= '<p>No matching records.</p>'; }
        $page = max(1, (int) $vm['page']);
        $body .= '<nav class="oidc-pagination" aria-label="Record pages"><span>Page ' . $page . ' · ' . (int) $vm['total'] . ' records</span>';
        foreach (['Previous' => $page - 1, 'Next' => $page + 1] as $label => $candidate) {
            if ($candidate < 1 || ($candidate > $page && $page * (int) $vm['pageSize'] >= (int) $vm['total'])) { continue; }
            $body .= '<a href="' . self::e(Config::ENTRY . '?' . http_build_query(['action' => $kind, 'page' => $candidate, 'search' => $query['search']])) . '">' . $label . '</a>';
        }
        return $body . '</nav>';
    }

    private function auditTime(mixed $value): string
    {
        if (!is_int($value) && !(is_string($value) && preg_match('/\A(?:0|[1-9][0-9]{0,11})\z/D', $value))) { return 'Unknown'; }
        $epoch = (int) $value;
        if ($epoch < 0 || $epoch > 253402300799) { return 'Unknown'; }
        return '<time datetime="' . gmdate('Y-m-d\TH:i:s\Z', $epoch) . '" title="Unix timestamp: ' . $epoch . '">' . gmdate('Y-m-d H:i:s', $epoch) . ' UTC</time>';
    }

    private function browser(array $cookies, bool $create): string
    {
        $value = $cookies[self::BROWSER_COOKIE] ?? null;
        if (!is_string($value) || !preg_match('/\A[0-9a-f]{64}\z/D', $value)) {
            if (!$create) { throw new AppException('BROWSER_BINDING_REQUIRED', 403); }
            $value = bin2hex(random_bytes(32));
        }
        if ($create) { $this->responseCookies[] = ['name' => self::BROWSER_COOKIE, 'value' => $value, 'options' => ['expires' => time() + 600, 'path' => self::COOKIE_PATH, 'secure' => true, 'httponly' => true, 'samesite' => 'Lax']]; }
        return $value;
    }
    private function navigation(): string { return '<nav class="oidc-nav" aria-label="OpenID Connect"><a href="' . Config::ENTRY . '">Settings</a><a href="' . Config::ENTRY . '?action=bindings">Account links</a><a href="' . Config::ENTRY . '?action=audit">Audit</a></nav>'; }
    private function recovery(bool $fresh = false): string { return '<p class="oidc-recovery">' . ($fresh ? '<a target="_blank" rel="noopener noreferrer" href="/nms/">Native account menu</a>' : '<a target="_top" href="/nms/login">Native password login</a>') . ' · <a href="' . Config::ENTRY . '">Plugin settings</a></p>'; }
    private function field(string $name, string $label, string $value, string $type = 'text'): string { return '<label for="oidc-' . $name . '">' . self::e($label) . '</label><input id="oidc-' . $name . '" name="' . $name . '" type="' . $type . '" maxlength="2048" value="' . self::e($value) . '">'; }
    private function select(string $name, string $label, string $value, array $options): string
    {
        $html = '<label for="oidc-' . $name . '">' . self::e($label) . '</label><select id="oidc-' . $name . '" name="' . $name . '">';
        foreach ($options as $key => $text) { $html .= '<option value="' . self::e($key) . '"' . ($key === $value ? ' selected' : '') . '>' . self::e($text) . '</option>'; }
        return $html . '</select>';
    }
    private function form(string $action, string $csrf, array $hidden, string $body, string $attributes = ''): string
    {
        $html = '<form method="post" action="' . Config::ENTRY . '?action=' . $action . '" ' . $attributes . '><input type="hidden" name="csrf" value="' . self::e($csrf) . '">';
        foreach ($hidden as $key => $value) { $html .= '<input type="hidden" name="' . self::e($key) . '" value="' . self::e($value) . '">'; }
        return $html . $body . '</form>';
    }
    private function bounded(array $input, int $count, int $limit): void
    {
        if (count($input) > $count) { throw new AppException('BAD_REQUEST'); }
        $bytes = 0;
        foreach ($input as $key => $value) {
            if (!is_string($key) || strlen($key) > 64 || !is_string($value) || strlen($value) > $limit || str_contains($value, "\0") || !mb_check_encoding($value, 'UTF-8')) { throw new AppException('BAD_REQUEST'); }
            $bytes += strlen($key) + strlen($value);
        }
        if ($bytes > 32768) { throw new AppException('REQUEST_TOO_LARGE', 413); }
    }
    private function uniqueQuery(array $server): void
    {
        $raw = $server['QUERY_STRING'] ?? '';
        if (!is_string($raw) || strlen($raw) > 16384) { throw new AppException('BAD_REQUEST'); }
        $seen = [];
        foreach (explode('&', $raw) as $part) {
            if ($part === '') { continue; }
            $key = urldecode(explode('=', $part, 2)[0]);
            if (isset($seen[$key]) || !preg_match('/\A[A-Za-z][A-Za-z0-9_-]{0,63}\z/D', $key)) { throw new AppException('BAD_REQUEST'); }
            $seen[$key] = true;
        }
    }
    private function text(mixed $value, int $length): string { if (!is_string($value) || strlen($value) > $length) { throw new AppException('BAD_REQUEST'); } return $value; }
    private function flow(mixed $value): string { if (!is_string($value) || !preg_match('/\A[0-9a-f]{64}\z/D', $value)) { throw new AppException('INVALID_FLOW'); } return $value; }
    private function flag(mixed $value): bool { if (!in_array($value, ['0', '1'], true)) { throw new AppException('BAD_REQUEST'); } return $value === '1'; }
    private function integer(mixed $value, int $minimum = 0): int { if (!is_string($value) || !preg_match('/\A(?:0|[1-9][0-9]{0,9})\z/D', $value) || (int) $value < $minimum || (int) $value > 2147483647) { throw new AppException('BAD_REQUEST'); } return (int) $value; }
    private function uuid(mixed $value): bool { return is_string($value) && preg_match('/\A[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\z/D', $value) === 1; }
    private static function e(string $value): string { return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'); }
    private function response(int $status, array $headers, string $body): array
    {
        return ['status' => $status, 'headers' => $headers + ['Cache-Control' => 'no-store, max-age=0', 'Pragma' => 'no-cache', 'Referrer-Policy' => 'no-referrer', 'X-Content-Type-Options' => 'nosniff',
            'Content-Security-Policy' => "default-src 'none'; script-src 'self'; style-src 'self'; font-src 'self'; img-src 'self'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'self'"], 'cookies' => $this->responseCookies, 'body' => $body];
    }
    private function json(array $value, int $status = 200, array $headers = []): array { return $this->response($status, $headers + ['Content-Type' => 'application/json; charset=UTF-8'], json_encode($value, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES)); }
    private function redirect(string $location): array { if (preg_match('/[\r\n]/', $location)) { throw new AppException('BAD_REQUEST'); } return $this->response(303, ['Location' => $location], ''); }
    private function page(string $title, string $body, int $status = 200, bool $nativeForm = false): array
    {
        // Navigation form POSTs serialize Origin:null under no-referrer. These
        // clean form pages (including authenticated recent-auth recovery) need same-origin for exact Origin+CSRF
        // validation; cross-origin provider navigations still get no Referer.
        // Callback/start redirects, completion, JSON, and other errors keep no-referrer.
        $headers = ['Content-Type' => 'text/html; charset=UTF-8'];
        if ($nativeForm && in_array($status, [200, 403], true)) { $headers['Referrer-Policy'] = 'same-origin'; }
        return $this->response($status, $headers, '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>' . self::e($title) . '</title><link rel="stylesheet" href="/crm/dist/main.min.css"><link rel="stylesheet" href="' . self::ASSETS . 'web.css"><script defer src="' . self::ASSETS . 'web.js"></script>' . ($nativeForm ? '<script defer src="' . self::ASSETS . 'settings-draft.js"></script>' : '') . '</head><body class="oidc-page"><main class="oidc-container"><h1>' . self::e($title) . '</h1>' . $body . '</main></body></html>');
    }
}
