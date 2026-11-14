<?php
declare(strict_types=1);
namespace UcrmOidc;

/** Durable logout bookkeeping; native session validation/revocation stays native. */
final class Logout
{
    private readonly \Closure $revoke;
    private readonly \Closure $clock;
    public function __construct(private readonly Store $store, private readonly Crypto $crypto,
        callable $revoke, callable $clock)
    {
        $this->revoke = \Closure::fromCallable($revoke);
        $this->clock = \Closure::fromCallable($clock);
    }
    private function now(): int { return ($this->clock)(); }
    private function hash(string $kind, string $issuer, string $client, string $value): string
    {
        return $this->crypto->digest('logout-' . $kind, $issuer . "\0" . $client . "\0" . $value);
    }
    private function sidScope(string $sidHash, ?string $subjectHash): string
    {
        return $this->crypto->digest('logout-sid-scope', $sidHash . "\0" . ($subjectHash ?? ''));
    }
    private function identity(array $identity): array
    {
        foreach (['issuer', 'clientId', 'subject'] as $name) {
            if (!is_string($identity[$name] ?? null) || $identity[$name] === '') { throw new AppException('FLOW_CONFIGURATION_CHANGED', 409); }
        }
        if (!is_int($identity['issuedAt'] ?? null) || $identity['issuedAt'] < 1 || !array_key_exists('sid', $identity)
            || ($identity['sid'] !== null && (!is_string($identity['sid']) || $identity['sid'] === ''))) {
            throw new AppException('FLOW_CONFIGURATION_CHANGED', 409);
        }
        return ['issuer' => $identity['issuer'], 'client_id' => $identity['clientId'],
            'subject_hash' => $this->hash('subject', $identity['issuer'], $identity['clientId'], $identity['subject']),
            'sid_hash' => $identity['sid'] === null ? null : $this->hash('sid', $identity['issuer'], $identity['clientId'], $identity['sid']),
            'identity_iat' => $identity['issuedAt']];
    }
    public function startFlow(string $id, array $settings): void
    {
        // sqlite_sequence survives removal of expired event rows.
        $sequence = (int) ($this->store->one("SELECT seq FROM sqlite_sequence WHERE name='logout_events'")['seq'] ?? 0);
        $this->store->run('INSERT INTO flow_context(flow_id,issuer,client_id,start_sequence) VALUES(?,?,?,?)',
            [$id, $settings['issuer'], $settings['clientId'], $sequence]);
    }
    public function assertFlow(array $flow, array $identity): array
    {
        $value = $this->identity($identity);
        $context = $this->store->one('SELECT * FROM flow_context WHERE flow_id=?', [$flow['id']]);
        if ($context === null || $context['issuer'] !== $value['issuer'] || $context['client_id'] !== $value['client_id']) {
            throw new AppException('FLOW_CONFIGURATION_CHANGED', 409);
        }
        $active = '(f.retain_until>? OR EXISTS(SELECT 1 FROM logout_events e WHERE e.issuer=f.issuer AND e.client_id=f.client_id AND e.status=\'pending\'))';
        $subject = $this->store->one('SELECT * FROM logout_fences f WHERE issuer=? AND client_id=? AND kind=? AND scope_hash=? AND ' . $active,
            [$value['issuer'], $value['client_id'], 'subject', $value['subject_hash'], $this->now()]);
        if ($subject !== null && ($value['identity_iat'] <= $subject['cutoff_iat'] || $context['start_sequence'] < $subject['last_sequence'])) {
            throw new AppException('PROVIDER_LOGGED_OUT', 403);
        }
        if ($value['sid_hash'] !== null && $this->store->one('SELECT scope_hash FROM logout_fences f WHERE issuer=? AND client_id=? AND kind=? AND scope_hash IN (?,?) AND ' . $active,
            [$value['issuer'], $value['client_id'], 'sid', $this->sidScope($value['sid_hash'], null),
                $this->sidScope($value['sid_hash'], $value['subject_hash']), $this->now()])) {
            throw new AppException('PROVIDER_LOGGED_OUT', 403);
        }
        return $value;
    }
    public function verifiedFlow(array $flow, array $identity): void
    {
        $value = $this->assertFlow($flow, $identity);
        if ($this->store->run('UPDATE flow_context SET subject_hash=?,sid_hash=?,identity_iat=? WHERE flow_id=?',
            [$value['subject_hash'], $value['sid_hash'], $value['identity_iat'], $flow['id']]) !== 1) {
            throw new AppException('FLOW_CONFIGURATION_CHANGED', 409);
        }
    }
    public function trackSession(string $sessionId, array $flow, array $identity): void
    {
        $value = $this->assertFlow($flow, $identity);
        $this->store->run('INSERT INTO session_context(session_id,issuer,client_id,subject_hash,sid_hash,identity_iat,flow_created_at) VALUES(?,?,?,?,?,?,?)',
            [$sessionId, $value['issuer'], $value['client_id'], $value['subject_hash'], $value['sid_hash'], $value['identity_iat'], $flow['created_at']]);
    }
    public function legacyPending(): bool
    {
        return ($this->store->one('SELECT value FROM meta WHERE key=?', ['logout_legacy_cleanup'])['value'] ?? '') !== 'complete'
            || $this->legacyRows();
    }
    private function legacyRows(): bool
    {
        return $this->store->one('SELECT s.id FROM sessions s LEFT JOIN session_context c ON c.session_id=s.id WHERE c.session_id IS NULL LIMIT 1') !== null
            || $this->store->one("SELECT f.id FROM flows f LEFT JOIN flow_context c ON c.flow_id=f.id WHERE c.flow_id IS NULL AND f.status NOT IN ('done','failed') LIMIT 1") !== null;
    }
    public function assertAdmission(): void
    {
        if ($this->legacyPending()) { throw new AppException('LEGACY_CLEANUP_PENDING', 503); }
    }
    public function prepareLegacy(): void
    {
        $this->store->tx(function (): void {
            $this->store->run('UPDATE sessions SET cleanup_pending=1 WHERE id IN (SELECT s.id FROM sessions s LEFT JOIN session_context c ON c.session_id=s.id WHERE c.session_id IS NULL)');
            foreach ($this->store->all("SELECT f.id FROM flows f LEFT JOIN flow_context c ON c.flow_id=f.id WHERE c.flow_id IS NULL AND f.status IN ('pending','verifying','verified','preview')") as $flow) {
                $this->store->run('UPDATE flows SET status=?,payload=? WHERE id=?', ['failed', $this->crypto->seal([], 'flow:' . $flow['id']), $flow['id']]);
            }
            $this->store->run("UPDATE flows SET expires_at=MIN(expires_at,CAST(? AS INTEGER)) WHERE id IN (SELECT f.id FROM flows f LEFT JOIN flow_context c ON c.flow_id=f.id WHERE c.flow_id IS NULL AND f.status IN ('mfa','issuing','cleanup'))", [$this->now()]);
            if ($this->legacyRows()) {
                $this->store->run('INSERT INTO meta(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value', ['logout_legacy_cleanup', 'required']);
            }
        });
    }
    public function finishLegacy(): void
    {
        $this->store->tx(function (): void {
            if (!$this->legacyRows()) {
                $this->store->run('INSERT INTO meta(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value', ['logout_legacy_cleanup', 'complete']);
            }
        });
    }
    private function retainFence(array $event, int $until): void
    {
        $kind = $event['sid_hash'] === null ? 'subject' : 'sid';
        $scope = $event['sid_hash'] === null ? $event['subject_hash'] : $this->sidScope($event['sid_hash'], $event['subject_hash']);
        $this->store->run('INSERT INTO logout_fences(issuer,client_id,kind,scope_hash,last_sequence,cutoff_iat,received_at,retain_until) VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(issuer,client_id,kind,scope_hash) DO UPDATE SET last_sequence=MAX(last_sequence,excluded.last_sequence),cutoff_iat=MAX(cutoff_iat,excluded.cutoff_iat),received_at=MAX(received_at,excluded.received_at),retain_until=MAX(retain_until,excluded.retain_until)',
            [$event['issuer'], $event['client_id'], $kind, $scope, $event['sequence'], $event['issued_at'], $event['received_at'], $until]);
    }
    /** Called under the same transaction as the current-registration recheck. */
    public function accept(array $claims): string
    {
        foreach (['issuer', 'clientId', 'jti'] as $name) {
            if (!is_string($claims[$name] ?? null) || $claims[$name] === '') { throw new AppException('LOGOUT_INVALID', 400); }
        }
        foreach (['subject', 'sid'] as $name) {
            if (!array_key_exists($name, $claims) || ($claims[$name] !== null && (!is_string($claims[$name]) || $claims[$name] === ''))) {
                throw new AppException('LOGOUT_INVALID', 400);
            }
        }
        if (($claims['subject'] === null && $claims['sid'] === null) || !is_int($claims['issuedAt'] ?? null)
            || !is_int($claims['expiresAt'] ?? null) || $claims['issuedAt'] < 1 || $claims['expiresAt'] <= $claims['issuedAt']) {
            throw new AppException('LOGOUT_INVALID', 400);
        }
        $issuer = $claims['issuer']; $client = $claims['clientId']; $now = $this->now();
        $subject = $claims['subject'] === null ? null : $this->hash('subject', $issuer, $client, $claims['subject']);
        $sid = $claims['sid'] === null ? null : $this->hash('sid', $issuer, $client, $claims['sid']);
        $jti = $this->hash('jti', $issuer, $client, $claims['jti']);
        $prior = $this->store->one('SELECT * FROM logout_events WHERE issuer=? AND client_id=? AND jti_hash=?', [$issuer, $client, $jti]);
        if ($prior !== null) {
            if ($prior['subject_hash'] !== $subject || $prior['sid_hash'] !== $sid) { throw new AppException('LOGOUT_INVALID', 400); }
            // Providers may renew iat/exp on transport retry. Preserve the first
            // event's fence, target set and ordering; only extend replay custody.
            $this->store->run('UPDATE logout_events SET expires_at=MAX(expires_at,CAST(? AS INTEGER)),replay_until=MAX(replay_until,CAST(? AS INTEGER)) WHERE id=?',
                [$claims['expiresAt'], max($claims['expiresAt'] + 30, $now + 32 * 86400), $prior['id']]);
            $this->retainFence($prior, max($claims['expiresAt'] + 30, $now + 32 * 86400));
            return $prior['id'];
        }
        $this->store->run('DELETE FROM logout_events WHERE status=? AND replay_until<=?', ['complete', $now]);
        if ((int) $this->store->one('SELECT COUNT(*) AS n FROM logout_events')['n'] >= 8192) { throw new AppException('STATE_UNAVAILABLE', 503); }
        $id = Crypto::random();
        $this->store->run('INSERT INTO logout_events(id,issuer,client_id,jti_hash,subject_hash,sid_hash,issued_at,received_at,expires_at,replay_until,status) VALUES(?,?,?,?,?,?,?,?,?,?,?)',
            [$id, $issuer, $client, $jti, $subject, $sid, $claims['issuedAt'], $now, $claims['expiresAt'], max($claims['expiresAt'] + 30, $now + 32 * 86400), 'pending']);
        $event = $this->store->one('SELECT * FROM logout_events WHERE id=?', [$id]);
        $kind = $sid === null ? 'subject' : 'sid';
        $this->retainFence($event, max($claims['expiresAt'] + 30, $now + 32 * 86400));
        $where = 'issuer=? AND client_id=?'; $parameters = [$issuer, $client];
        if ($sid !== null) { $where .= ' AND sid_hash=?'; $parameters[] = $sid; }
        if ($subject !== null) { $where .= ' AND subject_hash=?'; $parameters[] = $subject; }
        $this->store->run('INSERT INTO logout_targets(event_id,target_kind,target_id,status) SELECT ?,?,session_id,? FROM session_context WHERE ' . $where,
            [$id, 'session', 'pending', ...$parameters]);
        $this->store->run("INSERT INTO logout_targets(event_id,target_kind,target_id,status) SELECT ?,?,flow_id,? FROM flow_context WHERE " . $where
            . " AND flow_id IN (SELECT id FROM flows WHERE status NOT IN ('done','failed'))", [$id, 'flow', 'pending', ...$parameters]);
        $this->store->run('UPDATE sessions SET cleanup_pending=1 WHERE id IN (SELECT target_id FROM logout_targets WHERE event_id=? AND target_kind=?)', [$id, 'session']);
        $this->store->audit('logout.received', 'provider', $id, $kind, $now);
        return $id;
    }
    public function complete(string $id): bool
    {
        return $this->store->tx(function () use ($id): bool {
            if ($this->store->one('SELECT target_id FROM logout_targets WHERE event_id=? AND status=? LIMIT 1', [$id, 'pending'])) { return false; }
            if ($this->store->run('UPDATE logout_events SET status=? WHERE id=? AND status=?', ['complete', $id, 'pending']) === 1) {
                $this->store->audit('logout.completed', 'provider', $id, 'confirmed', $this->now());
            }
            return true;
        });
    }
    public function cleanupEvent(string $id, int $limit, int $deadline): int
    {
        if (hrtime(true) >= $deadline) { return 0; }
        $count = 0;
        $targets = $this->store->tx(function () use ($id, $limit): array {
            $rows = $this->store->all('SELECT * FROM logout_targets WHERE event_id=? AND status=? ORDER BY last_attempt,target_kind DESC,target_id LIMIT ' . $limit, [$id, 'pending']);
            // A global cursor makes both per-event and cross-event selection
            // fair even when older native artifacts cannot yet be revoked.
            $attempt = (int) ($this->store->one('SELECT MAX(last_attempt) AS n FROM logout_targets')['n'] ?? 0);
            foreach ($rows as $row) {
                $this->store->run('UPDATE logout_targets SET last_attempt=? WHERE event_id=? AND target_kind=? AND target_id=?',
                    [++$attempt, $id, $row['target_kind'], $row['target_id']]);
            }
            return $rows;
        });
        foreach ($targets as $target) {
            if (hrtime(true) >= $deadline) { break; }
            $done = false;
            try {
                if ($target['target_kind'] === 'session') {
                    $row = $this->store->one('SELECT * FROM sessions WHERE id=?', [$target['target_id']]);
                    if ($row === null) { $done = true; }
                    else {
                        $artifact = $this->crypto->open($row['artifact_enc'], 'session:' . $row['id']);
                        if (($this->revoke)($row['native_user_id'], 'session', $artifact['artifact'], $artifact['receipt'])) {
                            $this->store->run('DELETE FROM sessions WHERE id=? AND cleanup_pending=1', [$row['id']]); $done = true;
                        }
                    }
                } else {
                    $row = $this->store->one('SELECT * FROM flows WHERE id=?', [$target['target_id']]);
                    if ($row === null || in_array($row['status'], ['done', 'failed'], true)) { $done = true; }
                    elseif (!in_array($row['status'], ['issuing', 'uncertain'], true)) {
                        $payload = $this->crypto->open($row['payload'], 'flow:' . $row['id']);
                        $artifact = $payload['cleanup'] ?? (isset($payload['challenge']) ? ['kind' => 'mfa', 'artifact' => $payload['challenge']['twoFactorToken'], 'receipt' => $payload['challenge']['receipt']] : null);
                        if ($artifact === null || ($this->revoke)($payload['user']['id'], $artifact['kind'], $artifact['artifact'], $artifact['receipt'])) {
                            $done = $this->store->run('UPDATE flows SET status=?,payload=? WHERE id=? AND status=?',
                                ['failed', $this->crypto->seal([], 'flow:' . $row['id']), $row['id'], $row['status']]) === 1;
                        }
                    }
                }
            } catch (\Throwable) { /* Keep exact cleanup authority and target durable. */ }
            if ($done) {
                $this->store->run('UPDATE logout_targets SET status=? WHERE event_id=? AND target_kind=? AND target_id=?',
                    ['complete', $id, $target['target_kind'], $target['target_id']]); ++$count;
            }
        }
        $this->complete($id);
        return $count;
    }
    public function maintenance(int $deadline): int
    {
        $count = 0;
        foreach ($this->store->all("SELECT e.id FROM logout_events e LEFT JOIN logout_targets t ON t.event_id=e.id AND t.status='pending' WHERE e.status=? GROUP BY e.id ORDER BY COALESCE(MIN(t.last_attempt),0),e.sequence LIMIT 5", ['pending']) as $event) {
            if (hrtime(true) >= $deadline) { break; }
            $count += $this->cleanupEvent($event['id'], 5, $deadline);
        }
        $this->store->run('DELETE FROM logout_events WHERE status=? AND replay_until<=?', ['complete', $this->now()]);
        $this->store->run("DELETE FROM logout_fences WHERE retain_until<=? AND NOT EXISTS(SELECT 1 FROM logout_events e WHERE e.issuer=logout_fences.issuer AND e.client_id=logout_fences.client_id AND e.status='pending')", [$this->now()]);
        return $count;
    }
}
