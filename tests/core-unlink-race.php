<?php
declare(strict_types=1);
/** Real SQLite concurrency regression with an independent synthetic native spy. */
define('UCRM_OIDC_CONCURRENCY_FIXTURES_ONLY', true);
require __DIR__ . '/core-concurrency.php';

try {
    $f = fixture(); $login = login($f); callback($f, $login); sharedFixture($f);
    atomicJson($f['dir'] . '/control.json', ['pauseWorker' => 'issue', 'pauseOperation' => 'issue']);
    $worker = prepareWorker($f, 'issue', 'handoff', handoffPayload($login));
    ready($worker); go($worker); waitFile($f['dir'] . '/paused-issue');
    [$admin] = sharedApplication($f['dir'], 'unlink');
    $binding = $f['store']->one('SELECT * FROM bindings WHERE active=1');
    $unlinked = $admin->unlink($f['admin'], ['bindingId' => $binding['id'], 'expectedVersion' => $binding['version']]);
    atomicJson($f['dir'] . '/control.json', ['failRevoke' => true]);
    touch($f['dir'] . '/resume-issue'); $result = finish($worker);
    $flow = $f['store']->one('SELECT * FROM flows WHERE id=?', [$login['start']['flowId']]);
    $spy = readJson($f['dir'] . '/spy.json');
    $facts = ['browserPairDelivered' => $result['ok'], 'nativeIssueCalls' => issueCalls($f),
        'unlinkedBindingActive' => (bool) $f['store']->one('SELECT active FROM bindings WHERE id=?', [$binding['id']])['active'],
        'unlinkReportedPending' => $unlinked['pendingCleanup'], 'retainedFlow' => $flow !== null,
        'syntheticNativeSessions' => count($spy['sessions'])];
    check('concurrent unlink prevents browser pair delivery', !$result['ok']);
    check('unlink cannot retire authority for an in-flight native issuance', $flow !== null);
    $payload = $f['crypto']->open($flow['payload'], 'flow:' . $flow['id']);
    check('failed post-unlink revoke persists exact artifact receipt', $flow['status'] === 'cleanup' && isset($payload['cleanup']['receipt']));
    atomicJson($f['dir'] . '/control.json', []); [$reopened] = sharedApplication($f['dir'], 'retry'); $reopened->maintenance();
    check('maintenance later revokes the exact post-unlink artifact', count(readJson($f['dir'] . '/spy.json')['sessions']) === 0);

    // Inject a lost flow record while a different native request is in flight.
    // This is a storage fault fixture, not an asserted normal application path.
    $f = fixture(); $login = login($f); callback($f, $login); sharedFixture($f);
    atomicJson($f['dir'] . '/control.json', ['pauseWorker' => 'missing-row', 'pauseOperation' => 'issue']);
    $worker = prepareWorker($f, 'missing-row', 'handoff', handoffPayload($login));
    ready($worker); go($worker); waitFile($f['dir'] . '/paused-missing-row');
    $f['store']->run('DELETE FROM flows WHERE id=?', [$login['start']['flowId']]);
    atomicJson($f['dir'] . '/control.json', ['failRevoke' => true]);
    touch($f['dir'] . '/resume-missing-row'); $result = finish($worker);
    check('missing flow cannot release a newly issued pair to browser', !$result['ok']);
    check('missing flow rolls back session ledger instead of recording successful handoff', $f['store']->one('SELECT COUNT(*) AS n FROM sessions')['n'] === 0);
    $flow = $f['store']->one('SELECT * FROM flows WHERE id=?', [$login['start']['flowId']]);
    $payload = $flow === null ? [] : $f['crypto']->open($flow['payload'], 'flow:' . $flow['id']);
    check('missing flow recreates exact cleanup authority when native revoke fails', $flow !== null && $flow['status'] === 'cleanup' && isset($payload['cleanup']['receipt']));
    atomicJson($f['dir'] . '/control.json', []); [$reopened] = sharedApplication($f['dir'], 'missing-row-retry'); $reopened->maintenance();
    check('recreated cleanup authority later revokes only its issued artifact', count(readJson($f['dir'] . '/spy.json')['sessions']) === 0
        && $f['store']->one('SELECT id FROM flows WHERE id=?', [$login['start']['flowId']]) === null);
    echo json_encode(['scope' => 'SQLite-unlink-inflight-race-with-synthetic-native-spy', 'passed' => count($checks), 'facts' => $facts, 'checks' => $checks], JSON_PRETTY_PRINT), "\n";
} catch (Throwable $error) {
    echo json_encode(['scope' => 'SQLite-unlink-inflight-race-with-synthetic-native-spy',
        'passed' => count(array_filter($checks, fn($c) => $c['passed'])), 'failureType' => get_class($error),
        'facts' => $facts ?? [], 'checks' => $checks], JSON_PRETTY_PRINT), "\n";
    exit(1);
}
