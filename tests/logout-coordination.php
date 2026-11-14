<?php
declare(strict_types=1);
/** Real SQLite and RSA; native operations are a declared synthetic receipt spy. */
define('UCRM_OIDC_CONCURRENCY_FIXTURES_ONLY', true);
require __DIR__ . '/core-concurrency.php';

use UcrmOidc\{Application, Crypto, Logout, NativeSession, Oidc};
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\{RequestInterface, ResponseInterface};

function signedLogout(array $f, ?string $sid = null, ?string $subject = 'subject-1', array $overrides = []): string
{
    $claims = ['iss' => 'https://identity.example/oidc', 'aud' => 'test-client', 'iat' => time() - 1,
        'exp' => time() + 120, 'jti' => Crypto::random(),
        'events' => (object) ['http://schemas.openid.net/event/backchannel-logout' => (object) []]];
    if ($sid !== null) { $claims['sid'] = $sid; }
    if ($subject !== null) { $claims['sub'] = $subject; }
    $claims = array_replace($claims, $overrides);
    $input = b64(json_encode(['alg' => 'RS256', 'kid' => 'test-key', 'typ' => 'logout+jwt'])) . '.' . b64(json_encode($claims));
    openssl_sign($input, $signature, $f['provider']->key, OPENSSL_ALGO_SHA256);
    return $input . '.' . b64($signature);
}
function auditForLogout(): array { return ['remoteAddress' => '192.0.2.1', 'userAgent' => 'logout-unit']; }
function verifiedLogin(array $f, ?string $sid, array $claims = [], array $userinfo = []): array
{
    if ($sid !== null) { $claims['sid'] = $sid; }
    $claims += ['iat' => time() - 3];
    $login = login($f, $claims, $userinfo); callback($f, $login); return $login;
}
function issuedLogin(array $f, ?string $sid, array $claims = [], array $userinfo = []): array
{
    $login = verifiedLogin($f, $sid, $claims, $userinfo);
    $pair = $f['app']->handoff($login['browser'], $login['start']['flowId'], $login['audit'], null);
    return $login + ['pair' => $pair];
}
function trustedLogout(?string $sid, ?string $subject = 'subject-1'): array
{
    return ['issuer' => 'https://identity.example/oidc', 'clientId' => 'test-client', 'subject' => $subject,
        'sid' => $sid, 'issuedAt' => time() - 1, 'expiresAt' => time() + 120, 'jti' => Crypto::random()];
}
function contextIdentity(?string $sid): array
{
    return ['issuer' => 'https://identity.example/oidc', 'clientId' => 'test-client', 'subject' => 'subject-1',
        'sid' => $sid, 'issuedAt' => time() - 3];
}
function coordinator(array $f, callable $revoke): Logout { return new Logout($f['store'], $f['crypto'], $revoke, time(...)); }

final class DuringProviderRequest implements ClientInterface
{
    private bool $fired = false;
    public function __construct(private Provider $provider, private Closure $hook, private string $path = '/userinfo') {}
    public function sendRequest(RequestInterface $request): ResponseInterface
    {
        $reply = $this->provider->sendRequest($request);
        if (!$this->fired && $request->getUri()->getPath() === $this->path) { $this->fired = true; ($this->hook)(); }
        return $reply;
    }
}

try {
    $f = fixture();
    $password = uuid(); $f['adapter']->sessions[$password] = array_key_first($f['adapter']->users);
    $a = issuedLogin($f, 'provider-a'); $b = issuedLogin($f, 'provider-b');
    $binding = $f['store']->one('SELECT * FROM bindings');
    check('signed sid logout completes', $f['app']->backchannelLogout(signedLogout($f, 'provider-a'), auditForLogout())['ok']);
    check('sid event revokes only selected provider session', !isset($f['adapter']->sessions[$a['pair']['ucrmSessionId']])
        && isset($f['adapter']->sessions[$b['pair']['ucrmSessionId']], $f['adapter']->sessions[$password]));
    check('logout preserves native identity binding and its version', $f['store']->one('SELECT * FROM bindings') === $binding);
    check('sub event removes remaining owned session', $f['app']->backchannelLogout(signedLogout($f), auditForLogout())['ok']
        && array_keys($f['adapter']->sessions) === [$password]);
    check('native password artifact is absent from every target set', $f['store']->one('SELECT COUNT(*) AS n FROM logout_targets')['n'] === 2);
    denied('same sid cannot create a new native session', fn() => issuedLogin($f, 'provider-a', ['iat' => time() + 1]), 'PROVIDER_LOGGED_OUT');

    $f = fixture(); $a = issuedLogin($f, 'shared-sid');
    check('mismatched subject plus sid is no match', $f['app']->backchannelLogout(signedLogout($f, 'shared-sid', 'different-subject'), auditForLogout())['ok']
        && isset($f['adapter']->sessions[$a['pair']['ucrmSessionId']]));
    $b = issuedLogin($f, 'shared-sid');
    check('mismatched subject sid fence does not block actual subject', isset($f['adapter']->sessions[$b['pair']['ucrmSessionId']]));
    check('sid-only event selects both matching sessions', $f['app']->backchannelLogout(signedLogout($f, 'shared-sid', null), auditForLogout())['ok']
        && !$f['adapter']->sessions);

    $f = fixture(); $a = issuedLogin($f, 'client-a'); $b = issuedLogin($f, 'client-b');
    $f['store']->run('UPDATE session_context SET client_id=? WHERE session_id=?',
        ['other-registration', $f['crypto']->digest('session', $b['pair']['ucrmSessionId'])]);
    $f['app']->backchannelLogout(signedLogout($f), auditForLogout());
    check('current client cannot revoke another registration ledger', !isset($f['adapter']->sessions[$a['pair']['ucrmSessionId']])
        && isset($f['adapter']->sessions[$b['pair']['ucrmSessionId']]));

    $f = fixture(); $a = issuedLogin($f, 'prior-session'); $jti = Crypto::random();
    $first = signedLogout($f, null, 'subject-1', ['jti' => $jti]);
    $f['app']->backchannelLogout($first, auditForLogout());
    $before = $f['store']->one('SELECT * FROM logout_events');
    $b = issuedLogin($f, 'fresh-session', ['iat' => time() + 1]);
    check('new flow and newer verified ID token permit fresh sign-in', isset($f['adapter']->sessions[$b['pair']['ucrmSessionId']]));
    check('renewed same-jti retry succeeds without rescanning new login', $f['app']->backchannelLogout(signedLogout($f, null, 'subject-1',
        ['jti' => $jti, 'iat' => time() + 2, 'exp' => time() + 300]), auditForLogout())['ok']
        && isset($f['adapter']->sessions[$b['pair']['ucrmSessionId']]));
    $after = $f['store']->one('SELECT * FROM logout_events');
    check('renewed retry preserves original scope sequence and cutoff',
        array_intersect_key($before, array_flip(['id', 'sequence', 'issued_at', 'received_at', 'subject_hash', 'sid_hash']))
        === array_intersect_key($after, array_flip(['id', 'sequence', 'issued_at', 'received_at', 'subject_hash', 'sid_hash'])));
    check('replay custody survives original JWT expiry', $after['replay_until'] >= time() + 31 * 86400);
    $f['app']->backchannelLogout($first, auditForLogout());
    $shorter = $f['store']->one('SELECT * FROM logout_events');
    check('shorter retry cannot shorten prior token or replay custody', $shorter['expires_at'] === $after['expires_at']
        && $shorter['replay_until'] >= $after['replay_until']);
    denied('same jti cannot change event scope', fn() => $f['app']->backchannelLogout(signedLogout($f, 'fresh-session', 'subject-1', ['jti' => $jti]), auditForLogout()), 'LOGOUT_INVALID');

    $f = fixture(); $token = signedLogout($f);
    $wrapped = new DuringProviderRequest($f['provider'], function () use (&$f, $token): void {
        check('logout before first-link callback publication completes without match', $f['app']->backchannelLogout($token, auditForLogout())['ok']);
    });
    $f['oidc'] = new Oidc($f['store'], fn() => $wrapped);
    $f['app'] = new Application($f['store'], $f['crypto'], $f['native'], $f['oidc']);
    $pending = login($f, ['iat' => time() + 1]);
    denied('event sequence fences a first-link callback whose newer token arrives late', fn() => callback($f, $pending), 'PROVIDER_LOGGED_OUT');
    check('fenced first callback creates no binding or native artifact', $f['store']->one('SELECT COUNT(*) AS n FROM bindings')['n'] === 0 && $f['adapter']->issues === 0);

    $f = fixture(); $pending = verifiedLogin($f, 'verified-before-logout');
    $logout = coordinator($f, fn() => true);
    $f['store']->tx(fn() => $logout->accept(trustedLogout('verified-before-logout')));
    denied('durable fence blocks handoff before asynchronous cleanup runs', fn() => $f['app']->handoff(
        $pending['browser'], $pending['start']['flowId'], $pending['audit'], null), 'PROVIDER_LOGGED_OUT');
    check('fenced verified flow never reaches native issuance', $f['adapter']->issues === 0);

    $f = fixture(); $uid = array_key_first($f['adapter']->users); $f['adapter']->users[$uid]['totpAuthEnabled'] = true;
    $pending = issuedLogin($f, 'waiting-mfa');
    check('logout revokes a waiting native MFA challenge', $f['app']->backchannelLogout(signedLogout($f, 'waiting-mfa'), auditForLogout())['ok']
        && !$f['adapter']->challenges && !$f['adapter']->sessions);
    denied('a logged-out MFA flow cannot complete', fn() => $f['app']->completeMfa(
        $pending['browser'], $pending['start']['flowId'], '123456', $pending['audit'], null), 'FLOW_USED');

    $f = fixture(); $a = issuedLogin($f, 'disabled-signin'); $f['adapter']->enabled = false;
    check('disabled new sign-in does not suppress authenticated logout cleanup', !$f['app']->status()['ready']
        && $f['app']->backchannelLogout(signedLogout($f, 'disabled-signin'), auditForLogout())['ok'] && !$f['adapter']->sessions);

    $f = fixture(); $a = issuedLogin($f, 'cleared-secret');
    $revision = $f['app']->setup($f['admin'])['credentialRevision'];
    $f['app']->clearSecret($f['admin'], ['expectedCredentialRevision' => $revision]);
    check('signed logout needs no client secret after the secret is cleared', !$f['app']->status()['ready']
        && $f['app']->backchannelLogout(signedLogout($f, 'cleared-secret'), auditForLogout())['ok'] && !$f['adapter']->sessions);

    $f = fixture(); $a = issuedLogin($f, 'registration-race'); $token = signedLogout($f, 'registration-race');
    $f['store']->run('DELETE FROM cache');
    $wrapped = new DuringProviderRequest($f['provider'], function () use (&$f): void {
        $revision = $f['app']->setup($f['admin'])['credentialRevision'];
        $f['app']->replaceSecret($f['admin'], ['expectedCredentialRevision' => $revision, 'clientSecret' => 'rotated-synthetic-secret']);
    }, '/jwks');
    $f['oidc'] = new Oidc($f['store'], fn() => $wrapped);
    $f['app'] = new Application($f['store'], $f['crypto'], $f['native'], $f['oidc']);
    denied('registration revision is rechecked after signature verification', fn() => $f['app']->backchannelLogout($token, auditForLogout()), 'LOGOUT_INVALID');
    check('configuration race persists no event and revokes no session', $f['store']->one('SELECT COUNT(*) AS n FROM logout_events')['n'] === 0
        && isset($f['adapter']->sessions[$a['pair']['ucrmSessionId']]));

    $f = fixture(); $a = issuedLogin($f, 'restart-before-dispatch'); sharedFixture($f);
    $logout = coordinator($f, fn() => false);
    $event = $f['store']->tx(fn() => $logout->accept(trustedLogout('restart-before-dispatch')));
    $worker = prepareWorker($f, 'restart-after-event', 'maintenance', []);
    try {
        ready($worker); go($worker); $result = finish($worker);
        check('fresh process resumes durable event accepted before dispatch', $result['ok'] && !readJson($f['dir'] . '/spy.json')['sessions']
            && $f['store']->one('SELECT status FROM logout_events WHERE id=?', [$event])['status'] === 'complete');
    } finally { if (is_resource($worker['process'])) { proc_terminate($worker['process'], 9); } }

    foreach ([false, true] as $mfa) {
        $f = fixture(); $uid = array_key_first($f['adapter']->users); $f['adapter']->users[$uid]['totpAuthEnabled'] = $mfa;
        $login = verifiedLogin($f, 'inflight');
        sharedFixture($f); [$app] = sharedApplication($f['dir'], 'observer');
        if ($mfa) { $app->handoff($login['browser'], $login['start']['flowId'], $login['audit'], null); }
        $operation = $mfa ? 'complete-mfa' : 'issue'; $name = $mfa ? 'mfa-race' : 'issue-race';
        atomicJson($f['dir'] . '/control.json', ['pauseWorker' => $name, 'pauseAfterOperation' => $operation]);
        $worker = prepareWorker($f, $name, $mfa ? 'mfa' : 'handoff', handoffPayload($login));
        try {
            ready($worker); go($worker); waitFile($f['dir'] . '/paused-after-' . $name);
            $token = signedLogout($f, 'inflight');
            denied($name . ' returns pending while native outcome is in flight', fn() => $app->backchannelLogout($token, auditForLogout()), 'LOGOUT_PENDING');
            touch($f['dir'] . '/resume-' . $name); $result = finish($worker);
            check($name . ' cannot deliver native pair after logout fence', !$result['ok'] && $result['code'] === 'PROVIDER_LOGGED_OUT');
            check($name . ' revokes exact returned artifact before browser exposure', !readJson($f['dir'] . '/spy.json')['sessions']
                && !readJson($f['dir'] . '/spy.json')['challenges'] && $f['store']->one('SELECT COUNT(*) AS n FROM sessions')['n'] === 0);
            check($name . ' retry confirms scoped cleanup', $app->backchannelLogout($token, auditForLogout())['ok']);
        } finally { if (is_resource($worker['process'])) { proc_terminate($worker['process'], 9); } }
    }

    $f = fixture(); $login = issuedLogin($f, 'duplicate'); sharedFixture($f);
    $token = signedLogout($f, 'duplicate');
    $workers = [prepareWorker($f, 'logout-a', 'logout', ['token' => $token, 'audit' => auditForLogout()]),
        prepareWorker($f, 'logout-b', 'logout', ['token' => $token, 'audit' => auditForLogout()])];
    try {
        foreach ($workers as $worker) { ready($worker); } foreach ($workers as $worker) { go($worker); }
        $results = array_map(finish(...), $workers);
        check('parallel duplicate deliveries complete idempotently', $results[0]['ok'] && $results[1]['ok']);
        check('parallel delivery creates one durable event and target set', $f['store']->one('SELECT COUNT(*) AS n FROM logout_events')['n'] === 1
            && $f['store']->one('SELECT COUNT(*) AS n FROM logout_targets')['n'] === 1 && !readJson($f['dir'] . '/spy.json')['sessions']);
        check('duplicate delivery records one static confirmed completion audit', $f['store']->one('SELECT COUNT(*) AS n FROM audit WHERE event=? AND outcome=?',
            ['logout.completed', 'confirmed'])['n'] === 1);
    } finally { foreach ($workers as $worker) { if (is_resource($worker['process'])) { proc_terminate($worker['process'], 9); } } }

    $f = fixture(); $a = issuedLogin($f, 'pending-fence');
    $f['adapter']->unavailable = true;
    $token = signedLogout($f, 'pending-fence');
    denied('native outage retains pending event rather than acknowledging logout', fn() => $f['app']->backchannelLogout($token, auditForLogout()), 'LOGOUT_PENDING');
    $f['store']->run('UPDATE logout_fences SET retain_until=0');
    $f['app']->maintenance();
    check('expired fence row survives while native cleanup remains pending', $f['store']->one('SELECT COUNT(*) AS n FROM logout_fences')['n'] === 1);
    $logout = coordinator($f, fn() => false);
    $flow = $f['store']->one('SELECT * FROM flows WHERE id=?', [$a['start']['flowId']]);
    denied('pending cleanup keeps expired fence enforced', fn() => $logout->assertFlow($flow, contextIdentity('pending-fence')), 'PROVIDER_LOGGED_OUT');
    $f['adapter']->unavailable = false;
    check('retry completes cleanup after native recovery', $f['app']->backchannelLogout($token, auditForLogout())['ok'] && !$f['adapter']->sessions);
    check('same retry renews fence custody without dropping it', $f['store']->one('SELECT retain_until FROM logout_fences')['retain_until'] > time());

    $f = fixture(); for ($i = 0; $i < 6; ++$i) { issuedLogin($f, 'fair-' . $i); }
    $rows = $f['store']->all('SELECT id,artifact_enc FROM sessions ORDER BY id'); $blocked = [];
    foreach (array_slice($rows, 0, 5) as $row) { $blocked[] = $f['crypto']->open($row['artifact_enc'], 'session:' . $row['id'])['artifact']; }
    $last = $f['crypto']->open($rows[5]['artifact_enc'], 'session:' . $rows[5]['id'])['artifact'];
    $logout = coordinator($f, function ($uid, $kind, $artifact, $receipt) use (&$f, $blocked): bool {
        if (in_array($artifact, $blocked, true)) { return false; }
        unset($f['adapter']->sessions[$artifact]); return true;
    });
    $event = $f['store']->tx(fn() => $logout->accept(trustedLogout(null)));
    $logout->cleanupEvent($event, 5, hrtime(true) + 1_000_000_000);
    check('first bounded batch preserves failed cleanup receipts', count($f['adapter']->sessions) === 6);
    $logout->cleanupEvent($event, 5, hrtime(true) + 1_000_000_000);
    check('later valid receipt cannot starve behind first five failures', !isset($f['adapter']->sessions[$last]) && count($f['adapter']->sessions) === 5);
    check('partial cleanup remains pending and keeps fixed target set', !$logout->complete($event)
        && $f['store']->one('SELECT COUNT(*) AS n FROM logout_targets')['n'] === 6);

    $f = fixture(); $events = []; $blocked = []; $calls = 0;
    $logout = coordinator($f, function ($uid, $kind, $artifact, $receipt) use (&$f, &$blocked, &$calls): bool {
        ++$calls; if (in_array($artifact, $blocked, true)) { return false; }
        unset($f['adapter']->sessions[$artifact]); return true;
    });
    for ($i = 0; $i < 6; ++$i) {
        $a = issuedLogin($f, 'event-fair-' . $i);
        if ($i < 5) { $blocked[] = $a['pair']['ucrmSessionId']; } else { $last = $a['pair']['ucrmSessionId']; }
        $events[] = $f['store']->tx(fn() => $logout->accept(trustedLogout('event-fair-' . $i)));
    }
    $originalEvents = $f['store']->all('SELECT id,sequence,issued_at,received_at FROM logout_events ORDER BY sequence');
    $logout->maintenance(hrtime(true) + 1_000_000_000);
    check('event maintenance limits one pass to five pending events', $calls === 5 && count($f['adapter']->sessions) === 6);
    $logout->maintenance(hrtime(true) + 1_000_000_000);
    check('sixth event progresses despite five permanent earlier failures', !isset($f['adapter']->sessions[$last])
        && count($f['adapter']->sessions) === 5 && $logout->complete($events[5]));
    check('fair maintenance preserves original event sequence and cutoff', $originalEvents
        === $f['store']->all('SELECT id,sequence,issued_at,received_at FROM logout_events ORDER BY sequence'));
    $beforeCalls = $calls; $logout->maintenance(hrtime(true) - 1);
    check('expired dispatch budget makes no native cleanup call', $calls === $beforeCalls);

    $f = fixture(); $a = issuedLogin($f, 'legacy');
    $f['store']->run('DELETE FROM session_context');
    denied('unindexed legacy session blocks admission even with complete marker', fn() => login($f), 'LEGACY_CLEANUP_PENDING');
    $f['app']->maintenance();
    check('legacy cleanup uses recorded native receipt and reopens admission', !$f['adapter']->sessions && $f['app']->status()['ready']
        && $f['store']->one('SELECT value FROM meta WHERE key=?', ['logout_legacy_cleanup'])['value'] === 'complete');

    $f = fixture(); $uid = array_key_first($f['adapter']->users); $f['adapter']->users[$uid]['totpAuthEnabled'] = true;
    $a = issuedLogin($f, 'legacy-mfa'); $f['store']->run('DELETE FROM flow_context');
    denied('unindexed native MFA challenge gates new admission', fn() => login($f), 'LEGACY_CLEANUP_PENDING');
    $f['app']->maintenance();
    check('legacy MFA cleanup revokes only its recorded challenge', !$f['adapter']->challenges && $f['app']->status()['ready']);

    $f = fixture(); $a = verifiedLogin($f, 'legacy-uncertain');
    $flow = $f['store']->one('SELECT * FROM flows WHERE id=?', [$a['start']['flowId']]);
    $payload = $f['crypto']->open($flow['payload'], 'flow:' . $flow['id']); $payload['issuingAt'] = time() - 61;
    $f['store']->run('UPDATE flows SET status=?,payload=? WHERE id=?', ['issuing', $f['crypto']->seal($payload, 'flow:' . $flow['id']), $flow['id']]);
    $f['store']->run('DELETE FROM flow_context'); $f['app']->maintenance();
    check('legacy lost issuance stays uncertain and admission closed', $f['store']->one('SELECT status FROM flows WHERE id=?', [$flow['id']])['status'] === 'uncertain'
        && !$f['app']->status()['ready']);

    echo json_encode(['php' => PHP_VERSION, 'scope' => 'signed-library-real-SQLite-and-process-logout-coordination',
        'nativeBehaviorProven' => false, 'passed' => count($checks), 'checks' => $checks], JSON_PRETTY_PRINT), "\n";
} catch (Throwable $error) {
    echo json_encode(['php' => PHP_VERSION, 'passed' => count(array_filter($checks, fn($row) => $row['passed'])),
        'failureType' => get_class($error), 'safeCode' => $error->safeCode ?? null, 'checks' => $checks], JSON_PRETTY_PRINT), "\n";
    exit(1);
}
