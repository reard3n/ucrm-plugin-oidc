<?php
declare(strict_types=1);
namespace UcrmOidc;

final class Application
{
    private readonly \Closure $clock;
    private readonly Logout $logout;
    public function __construct(private readonly Store $store, private readonly Crypto $crypto,
        private readonly NativeSession $nativeSession, private readonly Oidc $oidc, ?callable $clock = null)
    {
        $this->clock = \Closure::fromCallable($clock ?? time(...));
        $this->logout = new Logout($store, $crypto, $this->revokeArtifact(...), $this->clock);
    }
    public static function boot(string $pluginRoot): self
    {
        $crypto = new Crypto(); $store = new Store($crypto);
        return new self($store, $crypto, new NativeSession($crypto), new Oidc($store));
    }
    private function now(): int { return ($this->clock)(); }
    public function native(): NativeSession { return $this->nativeSession; }
    private function settingsRow(): array { return $this->store->one('SELECT * FROM settings WHERE id=1'); }
    private function settings(array $row): array
    {
        return $row['config_json'] === null ? Config::DEFAULTS : json_decode($row['config_json'], true, 32, JSON_THROW_ON_ERROR);
    }
    private function credentialAad(array $settings, int $revision): string
    {
        return 'credential:' . $revision . ':' . hash('sha256', $settings['issuer'] . "\0" . $settings['clientId'] . "\0" . $settings['clientAuthMethod']);
    }
    private function secret(array $row, array $settings): ?string
    {
        if ($row['secret_enc'] === null) { return null; }
        $value = $this->crypto->open($row['secret_enc'], $this->credentialAad($settings, (int) $row['credential_revision']));
        if (!is_string($value['secret'] ?? null)) { throw new AppException('STATE_UNAVAILABLE', 503); }
        return $value['secret'];
    }
    private function snapshot(): array
    {
        $this->logout->assertAdmission();
        $row = $this->settingsRow(); $settings = $this->settings($row); $native = $this->native()->status();
        if (!$native['enabled']) { throw new AppException('OIDC_DISABLED', 403); }
        if ($row['config_json'] === null || ($settings['clientAuthMethod'] !== 'none' && $row['secret_enc'] === null)) { throw new AppException('SETUP_REQUIRED', 503); }
        return [$row, $settings, $native];
    }
    public function status(): array
    {
        $safe = ['enabled' => false, 'ready' => false, 'loginLabel' => Config::DEFAULTS['loginLabel'], 'startPath' => Config::ENTRY . '?action=start'];
        try {
            $row = $this->settingsRow(); $settings = $this->settings($row); $native = $this->native()->status();
            $safe['enabled'] = $native['enabled']; $safe['loginLabel'] = $settings['loginLabel'];
            $safe['ready'] = $native['enabled'] && !$this->logout->legacyPending() && $row['config_json'] !== null && ($settings['clientAuthMethod'] === 'none' || $row['secret_enc'] !== null);
        } catch (\Throwable) { /* Anonymous metadata exposes no diagnostics. */ }
        return $safe;
    }
    public function authorizationOrigins(): array
    {
        $row = $this->settingsRow();
        return $row['config_json'] === null ? [] : Config::origins($this->settings($row));
    }
    private function admin(array $context): void
    {
        if (($context['isClient'] ?? null) !== false || ($context['permissions']['system/plugins'] ?? '') !== 'edit'
            || !self::uuid($context['nativeUserId'] ?? null) || !self::uuid($context['sessionId'] ?? null)) {
            throw new AppException('ADMISSION_DENIED', 403);
        }
    }
    public function configuration(array $context): array
    {
        $this->admin($context); $row = $this->settingsRow(); $settings = $this->settings($row);
        try {
            $status = $this->native()->status();
            $native = ['enabled' => $status['enabled'], 'pluginEnabled' => $status['pluginEnabled'],
                'nativeVersion' => $status['nativeVersion'], 'nativeConfigRevision' => $status['configRevision']];
        } catch (\Throwable) { $native = ['enabled' => false, 'pluginEnabled' => false, 'nativeVersion' => null, 'nativeConfigRevision' => null]; }
        return ['settings' => $settings, 'providerRevision' => (int) $row['provider_revision'],
            'credentialRevision' => (int) $row['credential_revision'], 'secretPresent' => $row['secret_enc'] !== null,
            'callbackUrl' => $row['config_json'] === null ? null : Config::callback($settings), 'native' => $native,
            'backchannelLogoutUrl' => $row['config_json'] === null ? null : Config::backchannelLogout($settings),
            'legacyCleanupPending' => $this->logout->legacyPending(),
            'ready' => $native['enabled'] && !$this->logout->legacyPending() && $row['config_json'] !== null && ($settings['clientAuthMethod'] === 'none' || $row['secret_enc'] !== null)];
    }
    public function csrf(string $binding, string $purpose): string
    {
        return $this->crypto->csrf($binding, $purpose, intdiv($this->now(), 1800));
    }
    public function checkCsrf(string $binding, string $purpose, string $token): void
    {
        if (strlen($token) > 96) { throw new AppException('CSRF_DENIED', 403); }
        foreach ([intdiv($this->now(), 1800), intdiv($this->now(), 1800) - 1] as $bucket) {
            if (hash_equals($this->crypto->csrf($binding, $purpose, $bucket), $token)) { return; }
        }
        throw new AppException('CSRF_DENIED', 403);
    }
    public function assertFresh(array $context): void
    {
        $this->admin($context); $now = $this->now();
        if (!is_int($context['createdAt'] ?? null) || $context['createdAt'] < $now - 300 || $context['createdAt'] > $now + 30
            || !in_array($context['source'] ?? null, ['adapter', 'native-unattributed'], true)) { throw new AppException('RECENT_AUTH_REQUIRED', 403); }
        $ledger = $this->store->one('SELECT * FROM sessions WHERE id=?', [$this->crypto->digest('session', $context['sessionId'])]);
        if ($context['source'] === 'adapter' && $ledger === null) { throw new AppException('RECENT_AUTH_REQUIRED', 403); }
        if ($ledger !== null && ($ledger['native_user_id'] !== $context['nativeUserId'] || $ledger['auth_time'] === null
            || $ledger['auth_time'] < $now - 300 || $ledger['auth_time'] > $now + 30 || $ledger['cleanup_pending'])) { throw new AppException('RECENT_AUTH_REQUIRED', 403); }
    }
    public function saveSettings(array $context, array $input): array
    {
        $this->assertFresh($context); $expected = Config::revision($input['expectedProviderRevision'] ?? null); $settings = Config::settings($input);
        $this->store->tx(function () use ($context, $expected, $settings): void {
            $row = $this->settingsRow();
            if ((int) $row['provider_revision'] !== $expected) { throw new AppException('REVISION_CONFLICT', 409); }
            $previous = $this->settings($row);
            $trustChanged = $previous['issuer'] !== $settings['issuer'] || $previous['clientId'] !== $settings['clientId'] || $previous['clientAuthMethod'] !== $settings['clientAuthMethod'];
            $this->store->run('UPDATE settings SET config_json=?,provider_revision=provider_revision+1,secret_enc=?,credential_revision=? WHERE id=1',
                [json_encode($settings, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES), $trustChanged ? null : $row['secret_enc'],
                    (int) $row['credential_revision'] + ($trustChanged ? 1 : 0)]);
            $this->store->audit('settings.saved', $context['nativeUserId'], $settings['issuer'], $trustChanged ? 'credential_cleared' : 'saved', $this->now());
        });
        return $this->configuration($context);
    }
    public function replaceSecret(array $context, array $input): array
    {
        $this->assertFresh($context); Config::keys($input, ['expectedCredentialRevision', 'clientSecret']);
        $expected = Config::revision($input['expectedCredentialRevision'] ?? null); $secret = $input['clientSecret'] ?? null;
        if (!is_string($secret) || strlen($secret) > 4096 || preg_match('/[\x00-\x1f\x7f]/', $secret)) { throw new AppException('INVALID_CREDENTIAL'); }
        $this->store->tx(function () use ($context, $expected, $secret): void {
            $row = $this->settingsRow(); $settings = $this->settings($row);
            if ((int) $row['credential_revision'] !== $expected) { throw new AppException('REVISION_CONFLICT', 409); }
            if ($row['config_json'] === null) { throw new AppException('SETUP_REQUIRED'); }
            if ($secret === '') { return; }
            $revision = $expected + 1;
            $sealed = $this->crypto->seal(['secret' => $secret], $this->credentialAad($settings, $revision));
            $this->store->run('UPDATE settings SET secret_enc=?,credential_revision=? WHERE id=1', [$sealed, $revision]);
            $this->store->audit('credential.replaced', $context['nativeUserId'], $settings['issuer'], 'saved', $this->now());
        });
        return $this->configuration($context);
    }
    public function clearSecret(array $context, array $input): array
    {
        $this->assertFresh($context); Config::keys($input, ['expectedCredentialRevision']); $expected = Config::revision($input['expectedCredentialRevision'] ?? null);
        $this->store->tx(function () use ($context, $expected): void {
            if ($this->store->run('UPDATE settings SET secret_enc=NULL,credential_revision=credential_revision+1 WHERE id=1 AND credential_revision=?', [$expected]) !== 1) { throw new AppException('REVISION_CONFLICT', 409); }
            $this->store->audit('credential.cleared', $context['nativeUserId'], 'credential', 'saved', $this->now());
        });
        return $this->configuration($context);
    }
    public function connectionTest(array $context): array
    {
        $this->admin($context); $row = $this->settingsRow();
        if ($row['config_json'] === null) { throw new AppException('SETUP_REQUIRED'); }
        $settings = $this->settings($row); $metadata = $this->oidc->discovery($settings);
        $this->store->audit('provider.connection', $context['nativeUserId'], $settings['issuer'], 'passed', $this->now());
        return ['ok' => true, 'issuer' => $metadata['issuer'], 'callbackUrl' => Config::callback($settings),
            'checks' => ['HTTPS discovery', 'Exact issuer', 'Approved endpoint origins', 'Authorization code with PKCE S256', 'RS256'],
            'note' => 'Discovery passed. Test sign-in verifies client credentials and account matching.'];
    }
    public function setup(array $context): array
    {
        $this->admin($context); return $this->configuration($context);
    }
    public function records(array $context, string $kind, array $query): array
    {
        $this->admin($context); Config::keys($query, ['page', 'pageSize', 'search', 'active']);
        $page = filter_var($query['page'] ?? 1, FILTER_VALIDATE_INT); $size = filter_var($query['pageSize'] ?? 25, FILTER_VALIDATE_INT);
        $search = $query['search'] ?? '';
        if ($page === false || $page < 1 || $page > 100000 || $size === false || $size < 1 || $size > 100 || !is_string($search) || strlen($search) > 128) { throw new AppException('BAD_REQUEST'); }
        $limit = (int) $size; $offset = ($page - 1) * $size; $parameters = [];
        if ($kind === 'bindings') {
            $where = ' WHERE 1=1';
            if ($search !== '') { $where .= ' AND (instr(username,?)>0 OR instr(issuer,?)>0 OR native_user_id=?)'; $parameters = [$search, $search, $search]; }
            if (isset($query['active']) && $query['active'] !== '') {
                if (!in_array($query['active'], ['0', '1', 0, 1], true)) { throw new AppException('BAD_REQUEST'); }
                $where .= ' AND active=?'; $parameters[] = (int) $query['active'];
            }
            $total = (int) $this->store->one('SELECT COUNT(*) AS n FROM bindings' . $where, $parameters)['n'];
            $rows = $this->store->all('SELECT * FROM bindings' . $where . ' ORDER BY updated_at DESC,id LIMIT ' . $limit . ' OFFSET ' . $offset, $parameters);
            $items = array_map(function (array $row): array {
                $identity = $this->crypto->open($row['identity_enc'], 'binding:' . $row['id']);
                return ['id' => $row['id'], 'issuer' => $row['issuer'], 'subject' => $identity['subject'], 'nativeUserId' => $row['native_user_id'],
                    'username' => $row['username'], 'active' => (bool) $row['active'], 'version' => (int) $row['version'],
                    'createdAt' => (int) $row['created_at'], 'updatedAt' => (int) $row['updated_at']];
            }, $rows);
        } elseif ($kind === 'audit') {
            $where = $search === '' ? '' : ' WHERE instr(event,?)>0 OR instr(outcome,?)>0'; $parameters = $search === '' ? [] : [$search, $search];
            $total = (int) $this->store->one('SELECT COUNT(*) AS n FROM audit' . $where, $parameters)['n'];
            $items = $this->store->all('SELECT id,at,event,actor,object,outcome FROM audit' . $where . ' ORDER BY id DESC LIMIT ' . $limit . ' OFFSET ' . $offset, $parameters);
        } else { throw new AppException('BAD_REQUEST'); }
        return ['items' => $items, 'total' => $total, 'page' => $page, 'pageSize' => $size];
    }
    public function accountLookup(array $context, string $email): array
    {
        $this->admin($context);
        if (strlen($email) > 320 || !filter_var($email, FILTER_VALIDATE_EMAIL)) { throw new AppException('INVALID_EMAIL'); }
        $status = $this->native()->status();
        $user = $this->nativeUser('resolve', ['email' => $email], $status);
        return ['nativeUserId' => $user['id'], 'username' => $user['username'], 'email' => $user['email'], 'role' => $user['role'], 'ucrmRole' => $user['ucrmRole']];
    }
    public function unlink(array $context, array $input): array
    {
        $this->assertFresh($context); Config::keys($input, ['bindingId', 'expectedVersion']);
        $id = $input['bindingId'] ?? null; $version = Config::revision($input['expectedVersion'] ?? null);
        if (!Crypto::hex($id)) { throw new AppException('BAD_REQUEST'); }
        $this->store->tx(function () use ($context, $id, $version): void {
            if ($this->store->run('UPDATE bindings SET active=0,version=version+1,updated_at=? WHERE id=? AND version=?', [$this->now(), $id, $version]) !== 1) { throw new AppException('REVISION_CONFLICT', 409); }
            $this->store->run('UPDATE sessions SET cleanup_pending=1 WHERE binding_id=?', [$id]);
            $this->store->audit('binding.unlinked', $context['nativeUserId'], $id, 'blocked', $this->now());
        });
        $this->store->run('UPDATE flows SET expires_at=? WHERE binding_id=? AND status IN (?,?,?)', [$this->now(), $id, 'mfa', 'issuing', 'cleanup']);
        $this->maintenance();
        return ['ok' => true, 'pendingCleanup' => (int) $this->store->one('SELECT COUNT(*) AS n FROM sessions WHERE binding_id=? AND cleanup_pending=1', [$id])['n']
            + (int) $this->store->one('SELECT COUNT(*) AS n FROM flows WHERE binding_id=? AND status IN (?,?,?,?)', [$id, 'cleanup', 'mfa', 'issuing', 'uncertain'])['n']];
    }
    public function relink(array $context, array $input): array
    {
        $this->assertFresh($context); Config::keys($input, ['bindingId', 'nativeUserId', 'expectedVersion']);
        $id = $input['bindingId'] ?? null; $target = $input['nativeUserId'] ?? null; $version = Config::revision($input['expectedVersion'] ?? null);
        if (!Crypto::hex($id) || !self::uuid($target)) { throw new AppException('BAD_REQUEST'); }
        $native = $this->native()->status(); $user = $this->nativeUser('inspect', ['nativeUserId' => $target], $native);
        $this->store->tx(function () use ($context, $id, $target, $version, $user): void {
            $row = $this->store->one('SELECT * FROM bindings WHERE id=?', [$id]);
            if ($row === null || $row['version'] !== $version || $row['active']) { throw new AppException('UNLINK_BEFORE_RELINK', 409); }
            if ($this->store->one('SELECT id FROM bindings WHERE active=1 AND native_user_id=?', [$target])) { throw new AppException('BINDING_CONFLICT', 409); }
            if ($this->store->one('SELECT id FROM sessions WHERE binding_id=? AND cleanup_pending=1', [$id])
                || $this->store->one('SELECT id FROM flows WHERE binding_id=? AND status IN (?,?,?,?)', [$id, 'cleanup', 'mfa', 'issuing', 'uncertain'])) { throw new AppException('CLEANUP_PENDING', 409); }
            $this->store->run('UPDATE bindings SET native_user_id=?,username=?,active=1,version=version+1,updated_at=? WHERE id=?', [$target, $user['username'], $this->now(), $id]);
            $this->store->audit('binding.relinked', $context['nativeUserId'], $id, 'saved', $this->now());
        });
        return ['ok' => true];
    }
    private static function uuid(mixed $value): bool
    {
        return is_string($value) && preg_match('/\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\z/Di', $value) === 1;
    }
    private function nativeUser(string $operation, array $fields, array $status): array
    {
        $reply = $this->native()->call($operation, $fields + ['serverEpoch' => $status['serverEpoch'], 'configRevision' => $status['configRevision']]);
        $user = $reply['user'] ?? null;
        if (($reply['kind'] ?? '') !== 'user' || !is_array($user) || !self::uuid($user['id'] ?? null)
            || !is_string($user['username'] ?? null) || !is_string($user['email'] ?? null)
            || !is_string($user['role'] ?? null) || !array_key_exists('ucrmRole', $user)) { throw new AppException('NATIVE_UNAVAILABLE', 503); }
        return $user;
    }
    private function browser(string $browser): string
    {
        if (!Crypto::hex($browser)) { throw new AppException('FLOW_INVALID', 403); }
        return $this->crypto->digest('browser', $browser);
    }
    public function start(string $browser, string $returnPath, array $audit, ?array $previewContext = null, bool $fresh = false): array
    {
        $hash = $this->browser($browser); $returnPath = Config::returnPath($returnPath); $now = $this->now();
        if ($previewContext !== null) { $this->admin($previewContext); }
        $this->store->rate('start-global', 120, 60, $now);
        $this->store->rate($this->crypto->digest('start-ip', $audit['remoteAddress']), 20, 60, $now);
        $this->store->rate('start-browser:' . $hash, 10, 60, $now);
        [$row, $settings, $native] = $this->snapshot();
        $id = Crypto::random();
        $payload = ['state' => Crypto::random(), 'nonce' => Crypto::random(), 'code_verifier' => Crypto::random(),
            'maxAge' => $fresh ? 0 : $settings['maxAge'], 'returnPath' => $returnPath,
            'previewContext' => $previewContext === null ? null : array_intersect_key($previewContext, array_flip(['sessionId', 'nativeUserId']))];
        $this->store->tx(function () use ($row, $settings, $native, $id, $payload, $hash, $now): void {
            $this->logout->assertAdmission();
            $this->store->run('DELETE FROM flows WHERE expires_at<=? AND status NOT IN (?,?,?)', [$now, 'mfa', 'issuing', 'cleanup']);
            if ($this->store->one('SELECT COUNT(*) AS n FROM flows')['n'] >= 2048
                || $this->store->one('SELECT COUNT(*) AS n FROM flows WHERE expires_at>? AND status NOT IN (?,?)', [$now, 'done', 'failed'])['n'] >= 512
                || $this->store->one('SELECT COUNT(*) AS n FROM flows WHERE browser_hash=? AND expires_at>? AND status NOT IN (?,?)', [$hash, $now, 'done', 'failed'])['n'] >= 8) { throw new AppException('RATE_LIMITED', 429); }
            $this->store->run('INSERT INTO flows(id,state_hash,browser_hash,status,created_at,expires_at,provider_revision,credential_revision,native_revision,epoch,payload) VALUES(?,?,?,?,?,?,?,?,?,?,?)',
                [$id, $this->crypto->digest('state', $payload['state']), $hash, 'pending', $now, $now + 300,
                    $row['provider_revision'], $row['credential_revision'], $native['configRevision'], $native['serverEpoch'], $this->crypto->seal($payload, 'flow:' . $id)]);
            $this->logout->startFlow($id, $settings);
        });
        try { $url = $this->oidc->authorization($settings, $this->secret($row, $settings), $payload); }
        catch (\Throwable $error) { $this->failFlow($id); throw $error; }
        return ['authorizationUrl' => $url, 'flowId' => $id];
    }
    private function guard(array $flow): array
    {
        if ($flow['expires_at'] <= $this->now()) { throw new AppException('FLOW_EXPIRED', 403); }
        [$row, $settings, $native] = $this->snapshot();
        if ($row['provider_revision'] !== $flow['provider_revision'] || $row['credential_revision'] !== $flow['credential_revision']
            || $native['configRevision'] !== $flow['native_revision'] || $native['serverEpoch'] !== $flow['epoch']) { throw new AppException('FLOW_CONFIGURATION_CHANGED', 409); }
        return [$row, $settings, $native];
    }
    private function flow(string $browser, string $id): array
    {
        if (!Crypto::hex($id)) { throw new AppException('FLOW_INVALID', 403); }
        $row = $this->store->one('SELECT * FROM flows WHERE id=? AND browser_hash=?', [$id, $this->browser($browser)]);
        if ($row === null) { throw new AppException('FLOW_INVALID', 403); }
        return $row;
    }
    private function failFlow(string $id, bool $artifactRevoked = false, bool $uncertain = false): void
    {
        $row = $this->store->one('SELECT * FROM flows WHERE id=?', [$id]);
        if ($row === null || in_array($row['status'], ['done', 'uncertain'], true)) { return; }
        $payload = $this->crypto->open($row['payload'], 'flow:' . $id);
        if ($uncertain && !isset($payload['cleanup'])) {
            $this->store->run('UPDATE flows SET status=?,expires_at=? WHERE id=?', ['uncertain', $this->now() + 32 * 86400, $id]);
            $this->store->audit('login.issue_uncertain', $payload['user']['id'] ?? 'anonymous', $id, 'no_browser_handoff', $this->now());
            return;
        }
        if (!$artifactRevoked && (isset($payload['challenge']) || isset($payload['cleanup']))) {
            $this->store->run('UPDATE flows SET status=?,expires_at=? WHERE id=?', ['cleanup', $this->now(), $id]); return;
        }
        $this->store->run('UPDATE flows SET status=?,payload=? WHERE id=? AND status NOT IN (?,?)',
            ['failed', $this->crypto->seal([], 'flow:' . $id), $id, 'cleanup', 'done']);
    }
    private function binding(array $identity): ?array
    {
        return $this->store->one('SELECT * FROM bindings WHERE issuer=? AND subject_hash=?',
            [$identity['issuer'], $this->crypto->digest('subject', $identity['subject'])]);
    }
    private function resolveIdentity(array $identity, array $status): array
    {
        $binding = $this->binding($identity);
        if ($binding !== null) {
            if (!$binding['active']) { throw new AppException('IDENTITY_UNLINKED', 403); }
            return [$this->nativeUser('inspect', ['nativeUserId' => $binding['native_user_id']], $status), $binding];
        }
        if (!$identity['emailVerified'] || $identity['email'] === null) { throw new AppException('VERIFIED_EMAIL_REQUIRED', 403); }
        $user = $this->nativeUser('resolve', ['email' => $identity['email']], $status);
        if ($this->store->one('SELECT id FROM bindings WHERE native_user_id=? AND active=1', [$user['id']])) { throw new AppException('BINDING_CONFLICT', 409); }
        return [$user, null];
    }
    private function previewCaller(array $payload, array $audit, array $status): void
    {
        if ($payload['previewContext'] === null) { return; }
        $reply = $this->native()->call('describe-caller', ['callerSessionId' => $payload['previewContext']['sessionId'], 'audit' => $audit, 'serverEpoch' => $status['serverEpoch']]);
        if (($reply['nativeUserId'] ?? null) !== $payload['previewContext']['nativeUserId']) { throw new AppException('ADMISSION_DENIED', 403); }
    }
    public function callback(string $browser, array $parameters, array $audit): array
    {
        $hash = $this->browser($browser); $state = $parameters['state'] ?? null;
        if (!Crypto::hex($state)) { throw new AppException('FLOW_INVALID', 403); }
        $flow = $this->store->tx(function () use ($state, $hash): array {
            $row = $this->store->one('SELECT * FROM flows WHERE state_hash=? AND browser_hash=? AND status=? AND expires_at>?',
                [$this->crypto->digest('state', $state), $hash, 'pending', $this->now()]);
            if ($row === null) { throw new AppException('FLOW_INVALID', 403); }
            $this->store->run('UPDATE flows SET status=? WHERE id=?', ['verifying', $row['id']]); return $row;
        });
        try {
            [$row, $settings, $native] = $this->guard($flow);
            $payload = $this->crypto->open($flow['payload'], 'flow:' . $flow['id']);
            $identity = $this->oidc->verify($settings, $this->secret($row, $settings), $payload, $parameters);
            // No provider token is persisted. Only the validated identity remains.
            $this->previewCaller($payload, $audit, $native);
            [$user, $binding] = $this->resolveIdentity($identity, $native);
            $payload = ['identity' => $identity, 'user' => $user, 'bindingId' => $binding['id'] ?? null,
                'bindingVersion' => $binding['version'] ?? null, 'returnPath' => $payload['returnPath'], 'previewContext' => $payload['previewContext']];
            $this->store->tx(function () use ($flow, $payload): void {
                $this->guard($flow);
                $this->logout->verifiedFlow($flow, $payload['identity']);
                if ($this->store->run('UPDATE flows SET status=?,payload=? WHERE id=? AND status=?',
                    [$payload['previewContext'] === null ? 'verified' : 'preview', $this->crypto->seal($payload, 'flow:' . $flow['id']), $flow['id'], 'verifying']) !== 1) {
                    throw new AppException('FLOW_USED', 409);
                }
                $this->store->audit('login.verified', $payload['user']['id'], $flow['id'], $payload['previewContext'] === null ? 'verified' : 'preview', $this->now());
            });
        } catch (\Throwable $error) {
            $this->failFlow($flow['id']);
            $this->store->audit('login.denied', 'anonymous', $flow['id'], $error instanceof AppException || $error instanceof NativeSessionException ? $error->safeCode : 'AUTHENTICATION_DENIED', $this->now());
            throw $error;
        }
        return ['flowId' => $flow['id']];
    }
    public function completion(string $browser, string $flowId): array
    {
        $flow = $this->flow($browser, $flowId); $this->guard($flow);
        if (!in_array($flow['status'], ['verified', 'mfa', 'preview'], true)) { throw new AppException('FLOW_USED', 409); }
        $payload = $this->crypto->open($flow['payload'], 'flow:' . $flowId);
        $this->logout->assertFlow($flow, $payload['identity']);
        $view = ['kind' => $flow['status'] === 'verified' ? 'session' : $flow['status'], 'flowId' => $flowId, 'returnPath' => $payload['returnPath']];
        if ($flow['status'] === 'preview') {
            $identity = $payload['identity']; $user = $payload['user'];
            $view['previewRequiresAdminId'] = $payload['previewContext']['nativeUserId'];
            $view['preview'] = ['issuer' => $identity['issuer'], 'subject' => $identity['subject'], 'email' => $identity['email'], 'emailVerified' => $identity['emailVerified'],
                'username' => $user['username'], 'nativeUserId' => $user['id'], 'role' => $user['role'], 'ucrmRole' => $user['ucrmRole'],
                'alreadyLinked' => $payload['bindingId'] !== null, 'permissions' => 'Existing native permissions are retained.'];
        }
        return $view;
    }
    private function bindingForIssue(array $payload, array $native): array
    {
        [$user, $binding] = $this->resolveIdentity($payload['identity'], $native);
        if ($user['id'] !== $payload['user']['id']) { throw new AppException('IDENTITY_CHANGED', 409); }
        if ($payload['bindingId'] !== null && ($binding === null || $binding['id'] !== $payload['bindingId'] || $binding['version'] !== $payload['bindingVersion'])) { throw new AppException('BINDING_CHANGED', 409); }
        if ($binding !== null) { return $binding; }
        $id = Crypto::random(); $now = $this->now(); $identity = $payload['identity'];
        $this->store->run('INSERT INTO bindings VALUES(?,?,?,?,?,1,1,?,?,?)',
            [$id, $identity['issuer'], $this->crypto->digest('subject', $identity['subject']), $user['id'], $user['username'],
                $this->crypto->seal(['subject' => $identity['subject']], 'binding:' . $id), $now, $now]);
        $this->store->audit('binding.created', $user['id'], $id, 'verified_email', $now);
        return $this->store->one('SELECT * FROM bindings WHERE id=?', [$id]);
    }
    private function beginIssue(string $browser, string $flowId, ?array $currentUser, bool $mfa): array
    {
        return $this->store->tx(function () use ($browser, $flowId, $currentUser, $mfa): array {
            $flow = $this->flow($browser, $flowId); [, , $native] = $this->guard($flow);
            if ($flow['status'] !== ($mfa ? 'mfa' : 'verified')) { throw new AppException('FLOW_USED', 409); }
            $payload = $this->crypto->open($flow['payload'], 'flow:' . $flowId);
            $this->logout->assertFlow($flow, $payload['identity']);
            if ($payload['previewContext'] !== null) { throw new AppException('PREVIEW_ONLY', 403); }
            if ($currentUser !== null && ($currentUser['nativeUserId'] ?? null) !== $payload['user']['id']) { throw new AppException('SIGN_OUT_OTHER_ACCOUNT', 409); }
            $binding = $this->bindingForIssue($payload, $native);
            $payload['bindingId'] = $binding['id']; $payload['bindingVersion'] = $binding['version'];
            if (!$mfa) { $payload['transactionId'] = Crypto::random(); }
            $payload['issuingAt'] = $this->now();
            $this->store->run('UPDATE flows SET status=?,payload=?,binding_id=?,attempts=attempts+1 WHERE id=?',
                ['issuing', $this->crypto->seal($payload, 'flow:' . $flowId), $binding['id'], $flowId]);
            return [$flow, $payload, $native];
        });
    }
    public function handoff(string $browser, string $flowId, array $audit, ?array $currentUser): array
    {
        [$flow, $payload, $native] = $this->beginIssue($browser, $flowId, $currentUser, false);
        try {
            $now = $this->now();
            $reply = $this->native()->call('issue', ['nativeUserId' => $payload['user']['id'], 'transactionId' => $payload['transactionId'],
                'assertedAt' => $now, 'expiresAt' => $now + 60, 'serverEpoch' => $native['serverEpoch'], 'configRevision' => $native['configRevision'], 'audit' => $audit]);
            return $this->persistIssue($flow, $payload, $reply);
        } catch (\Throwable $error) {
            $this->failFlow($flowId, false, $error instanceof NativeSessionException && $error->safeCode === 'NATIVE_UNAVAILABLE');
            throw $error;
        }
    }
    public function completeMfa(string $browser, string $flowId, string $otp, array $audit, ?array $currentUser): array
    {
        if (!preg_match('/\A[0-9]{6}\z/D', $otp)) { throw new AppException('MFA_INVALID', 403); }
        $this->store->rate('mfa:' . $this->browser($browser), 10, 60, $this->now());
        [$flow, $payload, $native] = $this->beginIssue($browser, $flowId, $currentUser, true);
        try {
            $reply = $this->native()->call('complete-mfa', ['nativeUserId' => $payload['user']['id'], 'transactionId' => $payload['transactionId'],
                'twoFactorToken' => $payload['challenge']['twoFactorToken'], 'receipt' => $payload['challenge']['receipt'], 'verificationCode' => $otp,
                'serverEpoch' => $native['serverEpoch'], 'configRevision' => $native['configRevision'], 'audit' => $audit]);
            return $this->persistIssue($flow, $payload, $reply);
        } catch (NativeSessionException $error) {
            if ($error->safeCode === 'MFA_INVALID') {
                $this->store->run('UPDATE flows SET status=? WHERE id=? AND status=?', ['mfa', $flowId, 'issuing']);
            } else {
                $revoked = $this->revokeArtifact($payload['user']['id'], 'mfa', $payload['challenge']['twoFactorToken'], $payload['challenge']['receipt']);
                $this->failFlow($flowId, $revoked, $error->safeCode === 'NATIVE_UNAVAILABLE');
            }
            throw $error;
        } catch (\Throwable $error) {
            $revoked = $this->revokeArtifact($payload['user']['id'], 'mfa', $payload['challenge']['twoFactorToken'], $payload['challenge']['receipt']);
            $this->failFlow($flowId, $revoked); throw $error;
        }
    }
    private function persistIssue(array $flow, array $payload, array $reply): array
    {
        $kind = $reply['kind'] ?? null; $artifact = $kind === 'mfa' ? ($reply['twoFactorToken'] ?? null) : ($reply['ucrmSessionId'] ?? null);
        if (!in_array($kind, ['mfa', 'session'], true) || !self::uuid($artifact) || !is_string($reply['receipt'] ?? null)
            || $reply['receipt'] === '' || strlen($reply['receipt']) > 4096 || ($reply['user']['id'] ?? null) !== $payload['user']['id']) {
            // A malformed success may follow a completed native issuance, but
            // it provides no trustworthy scoped cleanup authority. Retain the
            // durable uncertainty exactly as for a lost transport response.
            throw new NativeSessionException('NATIVE_UNAVAILABLE');
        }
        try {
            $this->store->tx(function () use ($flow, $payload, $reply, $kind, $artifact): void {
                $this->guard($flow);
                $this->logout->assertFlow($flow, $payload['identity']);
                $binding = $this->store->one('SELECT * FROM bindings WHERE id=? AND active=1', [$payload['bindingId']]);
                if ($binding === null || $binding['version'] !== $payload['bindingVersion'] || $binding['native_user_id'] !== $payload['user']['id']) { throw new AppException('BINDING_CHANGED', 409); }
                if ($kind === 'mfa') {
                    if (!is_int($reply['expiresAt'] ?? null) || $reply['expiresAt'] <= $this->now()) { throw new AppException('MFA_EXPIRED', 403); }
                    $payload['challenge'] = ['twoFactorToken' => $artifact, 'receipt' => $reply['receipt'], 'expiresAt' => $reply['expiresAt']];
                    if ($this->store->run('UPDATE flows SET status=?,payload=? WHERE id=? AND status=?',
                        ['mfa', $this->crypto->seal($payload, 'flow:' . $flow['id']), $flow['id'], 'issuing']) !== 1) { throw new AppException('FLOW_USED', 409); }
                } else {
                    if (!self::uuid($reply['token'] ?? null) || !is_int($reply['createdAt'] ?? null) || !array_key_exists('cookieTtlMs', $reply)
                        || ($reply['cookieTtlMs'] !== null && (!is_int($reply['cookieTtlMs']) || $reply['cookieTtlMs'] < 1 || $reply['cookieTtlMs'] > 31 * 86400000))) { throw new AppException('NATIVE_UNAVAILABLE', 503); }
                    $digest = $this->crypto->digest('session', $artifact);
                    $this->store->run('INSERT INTO sessions VALUES(?,?,?,?,?,?,0,?)', [$digest, $binding['id'], $payload['user']['id'],
                        $reply['createdAt'], $payload['identity']['authTime'],
                        $this->crypto->seal(['artifact' => $artifact, 'receipt' => $reply['receipt']], 'session:' . $digest), $this->now() + 32 * 86400]);
                    $this->logout->trackSession($digest, $flow, $payload['identity']);
                    if ($this->store->run('UPDATE flows SET status=?,payload=? WHERE id=? AND status=?',
                        ['done', $this->crypto->seal([], 'flow:' . $flow['id']), $flow['id'], 'issuing']) !== 1) { throw new AppException('FLOW_USED', 409); }
                    $this->store->audit('login.completed', $payload['user']['id'], $flow['id'], 'native_session', $this->now());
                }
            });
        } catch (\Throwable $error) {
            if (!$this->revokeArtifact($payload['user']['id'], $kind, $artifact, $reply['receipt'])) {
                // If storage is still available, preserve the exact cleanup
                // authority. A storage outage never falls back to plaintext.
                try {
                    $payload['cleanup'] = ['kind' => $kind, 'artifact' => $artifact, 'receipt' => $reply['receipt']];
                    $this->store->run('INSERT INTO flows(id,state_hash,browser_hash,status,created_at,expires_at,provider_revision,credential_revision,native_revision,epoch,payload,attempts,binding_id) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET status=excluded.status,expires_at=excluded.expires_at,payload=excluded.payload,binding_id=excluded.binding_id',
                        [$flow['id'], $flow['state_hash'], $flow['browser_hash'], 'cleanup', $flow['created_at'], $this->now(),
                            $flow['provider_revision'], $flow['credential_revision'], $flow['native_revision'], $flow['epoch'],
                            $this->crypto->seal($payload, 'flow:' . $flow['id']), $flow['attempts'], $payload['bindingId']]);
                } catch (\Throwable) { /* No artifact is released to the browser. */ }
            }
            throw $error;
        }
        if ($kind === 'mfa') { return ['kind' => 'mfa']; }
        return ['kind' => 'session', 'token' => $reply['token'], 'ucrmSessionId' => $artifact,
            'cookieTtlMs' => $reply['cookieTtlMs'], 'returnPath' => $payload['returnPath']];
    }
    private function revokeArtifact(string $userId, string $kind, string $artifact, string $receipt): bool
    {
        try {
            $status = $this->native()->status();
            return ($this->native()->call('revoke', ['nativeUserId' => $userId, 'kind' => $kind, 'artifact' => $artifact, 'receipt' => $receipt, 'serverEpoch' => $status['serverEpoch']])['kind'] ?? null) === 'revoked';
        } catch (\Throwable) { return false; }
    }
    private function cleanupSessions(int $limit, ?string $bindingId = null, ?int $deadline = null): int
    {
        $rows = $this->store->all('SELECT * FROM sessions WHERE cleanup_pending=1' . ($bindingId === null ? '' : ' AND binding_id=?') . ' ORDER BY created_at LIMIT ' . $limit, $bindingId === null ? [] : [$bindingId]);
        $count = 0;
        foreach ($rows as $row) {
            if ($deadline !== null && hrtime(true) >= $deadline) { break; }
            $value = $this->crypto->open($row['artifact_enc'], 'session:' . $row['id']);
            if ($this->revokeArtifact($row['native_user_id'], 'session', $value['artifact'], $value['receipt'])) {
                $this->store->run('DELETE FROM sessions WHERE id=? AND cleanup_pending=1', [$row['id']]); ++$count;
                $this->store->audit('session.revoked', $row['native_user_id'], $row['binding_id'], 'completed', $this->now());
            }
        }
        return $count;
    }
    public function maintenance(): array
    {
        $cleaned = 0; $deadline = hrtime(true) + 15000000000;
        $this->logout->prepareLegacy();
        $now = $this->now();
        // The durable logout cursor must get its turn before generic cleanup,
        // whose oldest unavailable artifact may consume the dispatch budget.
        $logoutTargets = $this->logout->maintenance($deadline);
        foreach ($this->store->all('SELECT * FROM flows WHERE expires_at<=? AND status IN (?,?,?) ORDER BY expires_at LIMIT 5', [$now, 'mfa', 'issuing', 'cleanup']) as $flow) {
            if (hrtime(true) >= $deadline) { break; }
            $payload = $this->crypto->open($flow['payload'], 'flow:' . $flow['id']);
            if ($flow['status'] === 'issuing') {
                // An in-flight native request may still return an artifact and
                // needs its durable row. A crashed worker becomes a recorded
                // uncertainty, never an automatic retry or cleanup success.
                if (($payload['issuingAt'] ?? $flow['created_at']) + 60 <= $now) {
                    $this->failFlow($flow['id'], false, true);
                }
                continue;
            }
            $revoked = isset($payload['cleanup'])
                ? $this->revokeArtifact($payload['user']['id'], $payload['cleanup']['kind'], $payload['cleanup']['artifact'], $payload['cleanup']['receipt'])
                : (!isset($payload['challenge']) || $this->revokeArtifact($payload['user']['id'], 'mfa', $payload['challenge']['twoFactorToken'], $payload['challenge']['receipt']));
            if ($revoked) {
                $this->store->run('DELETE FROM flows WHERE id=? AND expires_at<=?', [$flow['id'], $now]); ++$cleaned;
                $this->store->audit('flow.cleaned', $payload['user']['id'] ?? 'anonymous', $flow['id'], 'completed', $now);
            }
        }
        $this->store->run('DELETE FROM flows WHERE expires_at<=? AND status NOT IN (?,?,?)', [$now, 'mfa', 'issuing', 'cleanup']);
        $this->store->run('DELETE FROM sessions WHERE expires_at<=? AND cleanup_pending=0', [$now]);
        $this->store->run('DELETE FROM cache WHERE expires_at<=?', [$now]);
        $this->store->run('DELETE FROM rates WHERE window_start<?', [$now - 3600]);
        $sessions = $this->cleanupSessions(5, null, $deadline);
        $this->logout->finishLegacy();
        return ['ok' => true, 'expiredFlowsCleaned' => $cleaned, 'sessionsRevoked' => $sessions,
            'logoutTargetsCleaned' => $logoutTargets, 'legacyCleanupPending' => $this->logout->legacyPending()];
    }

    public function backchannelLogout(string $token, array $audit): array
    {
        $now = $this->now();
        $this->store->rate('logout-global', 240, 60, $now);
        $this->store->rate($this->crypto->digest('logout-ip', $audit['remoteAddress']), 120, 60, $now);
        $row = $this->settingsRow();
        if ($row['config_json'] === null) { throw new AppException('SETUP_REQUIRED', 503); }
        $settings = $this->settings($row);
        $claims = $this->oidc->verifyLogout($settings, $token);
        $id = $this->store->tx(function () use ($row, $settings, $claims): string {
            $current = $this->settingsRow();
            if ($current['provider_revision'] !== $row['provider_revision'] || $current['credential_revision'] !== $row['credential_revision']
                || $claims['issuer'] !== $settings['issuer'] || $claims['clientId'] !== $settings['clientId']) {
                throw new AppException('LOGOUT_INVALID', 400);
            }
            return $this->logout->accept($claims);
        });
        $deadline = hrtime(true) + 15000000000;
        if ($this->logout->legacyPending()) { $this->maintenance(); }
        $this->logout->cleanupEvent($id, 5, $deadline);
        if ($this->logout->legacyPending() || !$this->logout->complete($id)) {
            throw new AppException('LOGOUT_PENDING', 400);
        }
        return ['ok' => true];
    }
}
