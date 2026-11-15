<?php
declare(strict_types=1);
/** Real SQLite/process tests. The native adapter below is a synthetic spy only. */
define('UCRM_OIDC_FIXTURES_ONLY', true);
require __DIR__ . '/core-unit.php';

use UcrmOidc\{Application,Crypto,Store,Oidc,NativeSession};

function atomicJson(string $path, array $value): void {
    $temporary = $path . '.' . getmypid() . '.tmp';
    file_put_contents($temporary, json_encode($value, JSON_THROW_ON_ERROR), LOCK_EX);
    chmod($temporary, 0600);
    if (!rename($temporary, $path)) { throw new RuntimeException('Test state write failed'); }
}
function readJson(string $path): array { return json_decode(file_get_contents($path), true, 32, JSON_THROW_ON_ERROR); }
function waitFile(string $path, float $seconds = 12): void {
    $deadline = hrtime(true) + (int) ($seconds * 1e9);
    while (!is_file($path)) {
        if (hrtime(true) >= $deadline) { throw new RuntimeException('Test synchronization deadline'); }
        usleep(10000);
    }
}

/** Independent locked ledger, never the SQLite database under test. */
final class SharedAdapterSpy {
    public function __construct(private string $directory, private Crypto $crypto, private string $worker) {}
    public function exchange(string $frame): string {
        $envelope = json_decode($frame, true, 16, JSON_THROW_ON_ERROR);
        $request = json_decode(base64_decode(strtr($envelope['body'], '-_', '+/')), true, 16, JSON_THROW_ON_ERROR);
        $operation = $request['operation'];
        $control = readJson($this->directory . '/control.json');
        if (($control['pauseWorker'] ?? null) === $this->worker && ($control['pauseOperation'] ?? null) === $operation
            && !is_file($this->directory . '/paused-' . $this->worker)) {
            touch($this->directory . '/paused-' . $this->worker);
            waitFile($this->directory . '/resume-' . $this->worker);
        }
        $handle = fopen($this->directory . '/spy.lock', 'c');
        if (!$handle || !flock($handle, LOCK_EX)) { throw new RuntimeException('Spy lock failed'); }
        try {
            $state = readJson($this->directory . '/spy.json');
            $adapter = new Adapter($this->crypto);
            foreach (['users','sessions','challenges','issues','enabled','epoch','revision','legacyMfa'] as $key) { $adapter->$key = $state[$key]; }
            $state['calls'][] = ['worker' => $this->worker, 'operation' => $operation];
            if (isset($control['failComplete']) && $operation === 'complete-mfa') {
                $response = json_encode(['ok' => false, 'error' => ['code' => $control['failComplete']]]) . "\n";
            } elseif (($control['failRevoke'] ?? false) && $operation === 'revoke') {
                $response = json_encode(['ok' => false, 'error' => ['code' => 'NATIVE_UNAVAILABLE']]) . "\n";
            } else {
                $response = $adapter->exchange($frame);
            }
            foreach (['users','sessions','challenges','issues','enabled','epoch','revision','legacyMfa'] as $key) { $state[$key] = $adapter->$key; }
            atomicJson($this->directory . '/spy.json', $state);
        } finally { flock($handle, LOCK_UN); fclose($handle); }
        if (($control['pauseWorker'] ?? null) === $this->worker && ($control['pauseAfterOperation'] ?? null) === $operation) {
            touch($this->directory . '/paused-after-' . $this->worker);
            waitFile($this->directory . '/resume-' . $this->worker);
        }
        if (($control['dropAfterOperation'] ?? null) === $operation) {
            return json_encode(['ok' => false, 'error' => ['code' => 'NATIVE_UNAVAILABLE']]) . "\n";
        }
        if (($control['malformOperation'] ?? null) === $operation) {
            $decoded = json_decode($response, true, 16, JSON_THROW_ON_ERROR);
            unset($decoded['result'][$control['omitField']]);
            return json_encode($decoded, JSON_THROW_ON_ERROR) . "\n";
        }
        return $response;
    }
}

function sharedFixture(array $fixture): array {
    $state = ['calls' => []];
    foreach (['users','sessions','challenges','issues','enabled','epoch','revision','legacyMfa'] as $key) { $state[$key] = $fixture['adapter']->$key; }
    atomicJson($fixture['dir'] . '/spy.json', $state);
    atomicJson($fixture['dir'] . '/control.json', []);
    return $fixture;
}
function sharedApplication(string $directory, string $worker, ?callable $clock = null): array {
    $crypto = new Crypto($directory . '/key');
    $store = new Store($crypto, $directory . '/state.sqlite');
    $spy = new SharedAdapterSpy($directory, $crypto, $worker);
    $native = new NativeSession($crypto, ['exchange' => $spy->exchange(...)]);
    $oidc = new Oidc($store, static fn() => new class implements \Psr\Http\Client\ClientInterface {
        public function sendRequest(\Psr\Http\Message\RequestInterface $request): \Psr\Http\Message\ResponseInterface
        { throw new RuntimeException('Unexpected provider network access from worker'); }
    });
    return [new Application($store, $crypto, $native, $oidc, $clock), $store];
}
function prepareWorker(array $fixture, string $name, string $operation, array $payload): array {
    $path = $fixture['dir'] . '/' . $name . '.json';
    atomicJson($path, ['directory' => $fixture['dir'], 'name' => $name, 'operation' => $operation, 'payload' => $payload]);
    $process = proc_open([PHP_BINARY, __FILE__, '--worker', $path],
        [0 => ['pipe','r'], 1 => ['pipe','w'], 2 => ['pipe','w']], $pipes);
    if (!is_resource($process)) { throw new RuntimeException('Worker creation failed'); }
    fclose($pipes[0]); stream_set_blocking($pipes[1], false); stream_set_blocking($pipes[2], false);
    return ['process' => $process, 'pipes' => $pipes, 'directory' => $fixture['dir'], 'name' => $name];
}
function ready(array $worker): void { waitFile($worker['directory'] . '/ready-' . $worker['name']); }
function go(array $worker): void { touch($worker['directory'] . '/go-' . $worker['name']); }
function finish(array $worker): array {
    $deadline = hrtime(true) + 15_000_000_000; $noise = '';
    try {
        while (true) {
            $noise .= stream_get_contents($worker['pipes'][1], 1025) . stream_get_contents($worker['pipes'][2], 1025);
            if (strlen($noise) > 2048) { throw new RuntimeException('Unexpected worker output'); }
            $status = proc_get_status($worker['process']);
            if (!$status['running']) { break; }
            if (hrtime(true) >= $deadline) { throw new RuntimeException('Worker deadline'); }
            usleep(10000);
        }
        if ($noise !== '') { throw new RuntimeException('Unexpected worker diagnostics'); }
        return readJson($worker['directory'] . '/result-' . $worker['name'] . '.json');
    } finally {
        $status = proc_get_status($worker['process']);
        if ($status['running']) { proc_terminate($worker['process'], 9); }
        fclose($worker['pipes'][1]); fclose($worker['pipes'][2]); proc_close($worker['process']);
    }
}
function handoffPayload(array $login): array {
    return ['browser' => $login['browser'], 'flowId' => $login['start']['flowId'], 'audit' => $login['audit']];
}
function killOwnedWorker(array $worker): void {
    // Only the process resource returned by this test's proc_open is signaled.
    $status = proc_get_status($worker['process']);
    if (!$status['running'] || !proc_terminate($worker['process'], 9)) { throw new RuntimeException('Owned worker not running'); }
    $deadline = hrtime(true) + 2_000_000_000;
    do {
        usleep(10000); $status = proc_get_status($worker['process']);
        if (hrtime(true) >= $deadline) { throw new RuntimeException('Owned worker termination deadline'); }
    } while ($status['running']);
    fclose($worker['pipes'][1]); fclose($worker['pipes'][2]); proc_close($worker['process']);
}
function issueCalls(array $fixture): int {
    return count(array_filter(readJson($fixture['dir'] . '/spy.json')['calls'], static fn(array $call): bool => $call['operation'] === 'issue'));
}
function parallel(array $fixture, array $payloads): array {
    $workers = [];
    foreach ($payloads as $name => $payload) { $workers[] = prepareWorker($fixture, $name, 'handoff', $payload); }
    try {
        foreach ($workers as $worker) { ready($worker); }
        // Hold the first native issue call outside SQLite. The second worker
        // must reject the conflict while that call is still in flight, rather
        // than merely arriving after a fast first worker has completed.
        atomicJson($fixture['dir'] . '/control.json', ['pauseWorker' => $workers[0]['name'], 'pauseOperation' => 'issue']);
        go($workers[0]); waitFile($fixture['dir'] . '/paused-' . $workers[0]['name']);
        go($workers[1]); $contender = finish($workers[1]);
        check($workers[0]['name'] . ' rejects competitor while native issuance remains in flight',
            !$contender['ok'] && !is_file($fixture['dir'] . '/result-' . $workers[0]['name'] . '.json'));
        touch($fixture['dir'] . '/resume-' . $workers[0]['name']);
        return [finish($workers[0]), $contender];
    } catch (Throwable $error) {
        foreach ($workers as $worker) { if (is_resource($worker['process'])) { proc_terminate($worker['process'], 9); } }
        throw $error;
    }
}

if (defined('UCRM_OIDC_CONCURRENCY_FIXTURES_ONLY')) { return; }

if (($argv[1] ?? '') === '--worker') {
    $spec = readJson($argv[2]); $directory = $spec['directory']; $name = $spec['name'];
    try {
        [$application, $store] = sharedApplication($directory, $name);
        touch($directory . '/ready-' . $name); waitFile($directory . '/go-' . $name);
        $started = hrtime(true); $payload = $spec['payload'];
        if ($spec['operation'] === 'handoff') {
            $value = $application->handoff($payload['browser'], $payload['flowId'], $payload['audit'], null);
            $result = ['ok' => true, 'kind' => $value['kind']];
        } elseif ($spec['operation'] === 'logout') {
            $value = $application->backchannelLogout($payload['token'], $payload['audit']);
            $result = ['ok' => $value['ok'], 'kind' => 'logout'];
        } elseif ($spec['operation'] === 'mfa') {
            $value = $application->completeMfa($payload['browser'], $payload['flowId'], '123456', $payload['audit'], null);
            $result = ['ok' => true, 'kind' => $value['kind']];
        } elseif ($spec['operation'] === 'maintenance') {
            $value = $application->maintenance();
            $result = ['ok' => $value['ok'], 'kind' => 'maintenance'];
        } elseif ($spec['operation'] === 'rotate') {
            $view = $application->configuration($payload['admin']);
            $settings = $view['settings']; $settings['loginLabel'] = 'Changed by concurrency test';
            $application->saveSettings($payload['admin'], $settings + ['expectedProviderRevision' => $view['providerRevision']]);
            $result = ['ok' => true, 'kind' => 'rotated'];
        } else { throw new RuntimeException('Unknown test operation'); }
    } catch (Throwable $error) {
        $result = ['ok' => false, 'code' => $error->safeCode ?? null, 'type' => get_class($error)];
    }
    $result['elapsedMs'] = isset($started) ? (int) ((hrtime(true) - $started) / 1e6) : 0;
    atomicJson($directory . '/result-' . $name . '.json', $result);
    exit(0);
}

try {
    $f = fixture(); $login = login($f); callback($f, $login); sharedFixture($f);
    $results = parallel($f, ['same-a' => handoffPayload($login), 'same-b' => handoffPayload($login)]);
    check('same flow concurrent workers deliver at most one session', count(array_filter($results, fn($r) => $r['ok'])) === 1);
    check('same flow loser is consumed without retry', count(array_filter($results, fn($r) => ($r['code'] ?? '') === 'FLOW_USED')) === 1);
    check('same flow makes exactly one external native issue call', issueCalls($f) === 1);
    check('same flow persists one active binding and one ledger entry',
        $f['store']->one('SELECT COUNT(*) AS n FROM bindings WHERE active=1')['n'] === 1
        && $f['store']->one('SELECT COUNT(*) AS n FROM sessions')['n'] === 1);

    $f = fixture(); $one = login($f, ['sub' => 'first-subject'], ['sub' => 'first-subject']); callback($f, $one);
    $two = login($f, ['sub' => 'second-subject'], ['sub' => 'second-subject']); callback($f, $two); sharedFixture($f);
    $results = parallel($f, ['subject-a' => handoffPayload($one), 'subject-b' => handoffPayload($two)]);
    check('parallel first links sharing native email have one winner', count(array_filter($results, fn($r) => $r['ok'])) === 1);
    check('parallel first link loser sees binding conflict', count(array_filter($results, fn($r) => ($r['code'] ?? '') === 'BINDING_CONFLICT')) === 1);
    check('parallel first links preserve database unique native binding', $f['store']->one('SELECT COUNT(*) AS n FROM bindings WHERE active=1')['n'] === 1);
    check('parallel first link conflict cannot issue second native pair', issueCalls($f) === 1);

    foreach ([false, true] as $verified) {
        $f = fixture(); $login = login($f); if ($verified) { callback($f, $login); } sharedFixture($f);
        $worker = prepareWorker($f, 'rotate', 'rotate', ['admin' => $f['admin']]); ready($worker); go($worker);
        check('independent process rotates provider configuration', finish($worker)['ok']);
        if ($verified) {
            [$app] = sharedApplication($f['dir'], 'after-rotation');
            denied('rotation rejects previously verified handoff', fn() => $app->handoff($login['browser'], $login['start']['flowId'], $login['audit'], null), 'FLOW_CONFIGURATION_CHANGED');
        } else {
            denied('rotation rejects pending callback before token exchange', fn() => callback($f, $login), 'FLOW_CONFIGURATION_CHANGED');
            check('configuration rotation made zero provider token calls', $f['provider']->tokenRequests === 0);
        }
        check('configuration rotation made zero native issue calls', issueCalls($f) === 0);
    }

    $f = fixture(); $secondId = '22222222-2222-4222-8222-222222222222';
    $second = reset($f['adapter']->users); $second['id'] = $secondId; $second['username'] = 'second'; $second['email'] = 'second@example.com';
    $f['adapter']->users[$secondId] = $second;
    $one = login($f); callback($f, $one);
    $two = login($f, ['sub' => 'second'], ['sub' => 'second', 'email' => 'second@example.com']); callback($f, $two); sharedFixture($f);
    atomicJson($f['dir'] . '/control.json', ['pauseWorker' => 'slow', 'pauseOperation' => 'status']);
    $slow = prepareWorker($f, 'slow', 'handoff', handoffPayload($one));
    $contender = prepareWorker($f, 'contender', 'handoff', handoffPayload($two));
    ready($slow); ready($contender); go($slow); waitFile($f['dir'] . '/paused-slow'); go($contender);
    $blocked = finish($contender); touch($f['dir'] . '/resume-slow'); $winner = finish($slow);
    check('stalled adapter causes bounded SQLite contention failure', !$blocked['ok'] && $blocked['type'] === PDOException::class
        && $blocked['elapsedMs'] >= 4500 && $blocked['elapsedMs'] < 8000);
    check('paused writer succeeds once after native adapter recovers', $winner['ok']);
    check('lock contention never automatically retries native issuance', issueCalls($f) === 1);
    check('contending flow remains unissued for explicit user recovery',
        $f['store']->one('SELECT status FROM flows WHERE id=?', [$two['start']['flowId']])['status'] === 'verified');
    check('lock contention produces only winner ledger and binding', $f['store']->one('SELECT COUNT(*) AS n FROM sessions')['n'] === 1
        && $f['store']->one('SELECT COUNT(*) AS n FROM bindings WHERE active=1')['n'] === 1);

    $f = fixture(); $uid = array_key_first($f['adapter']->users); $f['adapter']->legacyMfa = true; $f['adapter']->users[$uid]['totpAuthEnabled'] = true;
    $login = login($f); callback($f, $login); sharedFixture($f); [$app] = sharedApplication($f['dir'], 'mfa');
    check('unit MFA handoff exposes no challenge', $app->handoff($login['browser'], $login['start']['flowId'], $login['audit'], null) === ['kind' => 'mfa']);
    atomicJson($f['dir'] . '/control.json', ['failComplete' => 'MFA_EXPIRED', 'failRevoke' => true]);
    denied('known expired MFA and cleanup outage fails closed', fn() => $app->completeMfa($login['browser'], $login['start']['flowId'], '123456', $login['audit'], null), 'MFA_EXPIRED');
    $flow = $f['store']->one('SELECT * FROM flows WHERE id=?', [$login['start']['flowId']]);
    $payload = $f['crypto']->open($flow['payload'], 'flow:' . $flow['id']);
    check('failed cleanup retains encrypted native challenge receipt', $flow['status'] === 'cleanup' && isset($payload['challenge']['receipt']));
    check('failed MFA completion has no session ledger', $f['store']->one('SELECT COUNT(*) AS n FROM sessions')['n'] === 0);
    check('unavailable native cleanup leaves challenge queued', count(readJson($f['dir'] . '/spy.json')['challenges']) === 1);
    $app->maintenance(); check('maintenance failure preserves retry record', $f['store']->one('SELECT status FROM flows WHERE id=?', [$flow['id']])['status'] === 'cleanup');
    atomicJson($f['dir'] . '/control.json', []); [$restarted] = sharedApplication($f['dir'], 'maintenance-after-restart');
    $restarted->maintenance();
    check('reopened application retries exact native challenge cleanup', count(readJson($f['dir'] . '/spy.json')['challenges']) === 0);
    check('successful cleanup retires queued flow', $f['store']->one('SELECT id FROM flows WHERE id=?', [$flow['id']]) === null);

    $f = fixture(); $uid = array_key_first($f['adapter']->users); $f['adapter']->legacyMfa = true; $f['adapter']->users[$uid]['totpAuthEnabled'] = true;
    $login = login($f); callback($f, $login); sharedFixture($f); [$app] = sharedApplication($f['dir'], 'lost-mfa-response');
    $app->handoff($login['browser'], $login['start']['flowId'], $login['audit'], null);
    atomicJson($f['dir'] . '/control.json', ['dropAfterOperation' => 'complete-mfa']);
    denied('lost response after synthetic MFA issuance never delivers browser pair',
        fn() => $app->completeMfa($login['browser'], $login['start']['flowId'], '123456', $login['audit'], null), 'NATIVE_UNAVAILABLE');
    $flow = $f['store']->one('SELECT * FROM flows WHERE id=?', [$login['start']['flowId']]);
    $spy = readJson($f['dir'] . '/spy.json');
    check('uncertain MFA outcome retains durable 32 day review state', $flow['status'] === 'uncertain' && $flow['expires_at'] >= time() + 32 * 86400 - 2);
    check('synthetic completed MFA can exist without returned artifact or browser ledger', count($spy['sessions']) === 1 && count($spy['challenges']) === 0
        && $f['store']->one('SELECT COUNT(*) AS n FROM sessions')['n'] === 0);
    $binding = $f['store']->one('SELECT * FROM bindings WHERE active=1');
    $unlinked = $app->unlink($f['admin'], ['bindingId' => $binding['id'], 'expectedVersion' => $binding['version']]);
    check('unlink honestly reports uncertain native issuance as pending', $unlinked['pendingCleanup'] === 1);
    denied('uncertain native issuance prevents relink', fn() => $app->relink($f['admin'],
        ['bindingId' => $binding['id'], 'nativeUserId' => $uid, 'expectedVersion' => $binding['version'] + 1]), 'CLEANUP_PENDING');
    $app->maintenance();
    check('maintenance neither retries uncertain MFA nor claims unknown pair revoked', issueCalls($f) === 1
        && count(readJson($f['dir'] . '/spy.json')['sessions']) === 1
        && $f['store']->one('SELECT status FROM flows WHERE id=?', [$flow['id']])['status'] === 'uncertain');

    $f = fixture(); $login = login($f); callback($f, $login); sharedFixture($f);
    atomicJson($f['dir'] . '/control.json', ['pauseWorker' => 'abandoned', 'pauseAfterOperation' => 'issue']);
    $abandoned = prepareWorker($f, 'abandoned', 'handoff', handoffPayload($login));
    ready($abandoned); go($abandoned); waitFile($f['dir'] . '/paused-after-abandoned');
    $flow = $f['store']->one('SELECT * FROM flows WHERE id=?', [$login['start']['flowId']]);
    $payload = $f['crypto']->open($flow['payload'], 'flow:' . $flow['id']);
    check('worker durably records issuance time before external call', $flow['status'] === 'issuing' && is_int($payload['issuingAt'] ?? null));
    killOwnedWorker($abandoned);
    [$admin] = sharedApplication($f['dir'], 'abandoned-unlink'); $binding = $f['store']->one('SELECT * FROM bindings WHERE active=1');
    $unlinked = $admin->unlink($f['admin'], ['bindingId' => $binding['id'], 'expectedVersion' => $binding['version']]);
    check('recent crashed worker retains pending authority before abandonment deadline', $unlinked['pendingCleanup'] === 1
        && $f['store']->one('SELECT status FROM flows WHERE id=?', [$flow['id']])['status'] === 'issuing');
    $later = $payload['issuingAt'] + 61;
    [$reopened] = sharedApplication($f['dir'], 'after-crash', static fn(): int => $later); $reopened->maintenance();
    $retained = $f['store']->one('SELECT * FROM flows WHERE id=?', [$flow['id']]);
    check('abandoned process becomes durable uncertainty after grace', $retained['status'] === 'uncertain' && $retained['expires_at'] === $later + 32 * 86400);
    check('abandoned process never retries issue or creates a browser ledger', issueCalls($f) === 1
        && count(readJson($f['dir'] . '/spy.json')['sessions']) === 1
        && $f['store']->one('SELECT COUNT(*) AS n FROM sessions')['n'] === 0);
    check('abandoned process records uncertainty without cleanup success',
        $f['store']->one('SELECT COUNT(*) AS n FROM audit WHERE event=?', ['login.issue_uncertain'])['n'] === 1
        && $f['store']->one('SELECT COUNT(*) AS n FROM audit WHERE event=?', ['flow.cleaned'])['n'] === 0);

    foreach (['receipt', 'kind', 'user', 'ucrmSessionId'] as $missing) {
        $f = fixture(); $login = login($f); callback($f, $login); sharedFixture($f);
        [$app] = sharedApplication($f['dir'], 'malformed-' . $missing);
        atomicJson($f['dir'] . '/control.json', ['malformOperation' => 'issue', 'omitField' => $missing]);
        denied('malformed successful issuance missing ' . $missing . ' cannot hand off',
            fn() => $app->handoff($login['browser'], $login['start']['flowId'], $login['audit'], null), 'NATIVE_UNAVAILABLE');
        check('malformed successful issuance missing ' . $missing . ' retains uncertainty',
            $f['store']->one('SELECT status FROM flows WHERE id=?', [$login['start']['flowId']])['status'] === 'uncertain');
        $app->maintenance();
        check('malformed successful issuance missing ' . $missing . ' has no retry or false browser ledger', issueCalls($f) === 1
            && count(readJson($f['dir'] . '/spy.json')['sessions']) === 1
            && $f['store']->one('SELECT COUNT(*) AS n FROM sessions')['n'] === 0);
    }
    $f = fixture(); $uid = array_key_first($f['adapter']->users); $f['adapter']->legacyMfa = true; $f['adapter']->users[$uid]['totpAuthEnabled'] = true;
    $login = login($f); callback($f, $login); sharedFixture($f); [$app] = sharedApplication($f['dir'], 'malformed-mfa-success');
    $app->handoff($login['browser'], $login['start']['flowId'], $login['audit'], null);
    atomicJson($f['dir'] . '/control.json', ['malformOperation' => 'complete-mfa', 'omitField' => 'receipt']);
    denied('malformed success after completed MFA cannot hand off',
        fn() => $app->completeMfa($login['browser'], $login['start']['flowId'], '123456', $login['audit'], null), 'NATIVE_UNAVAILABLE');
    check('malformed MFA success preserves uncertainty despite stale challenge revoke',
        $f['store']->one('SELECT status FROM flows WHERE id=?', [$login['start']['flowId']])['status'] === 'uncertain'
        && count(readJson($f['dir'] . '/spy.json')['sessions']) === 1
        && $f['store']->one('SELECT COUNT(*) AS n FROM sessions')['n'] === 0);

    echo json_encode(['php' => PHP_VERSION, 'scope' => 'multiprocess-real-SQLite-with-synthetic-native-spy',
        'nativeBehaviorProven' => false, 'passed' => count($checks), 'checks' => $checks], JSON_PRETTY_PRINT), "\n";
} catch (Throwable $error) {
    echo json_encode(['php' => PHP_VERSION, 'scope' => 'multiprocess-real-SQLite-with-synthetic-native-spy',
        'passed' => count(array_filter($checks, fn($c) => $c['passed'])), 'failureType' => get_class($error), 'checks' => $checks], JSON_PRETTY_PRINT), "\n";
    exit(1);
}
