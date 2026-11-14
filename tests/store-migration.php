<?php
declare(strict_types=1);
/** Real SQLite only; all keys, receipts and state are synthetic in this process's /tmp. */
$worker = $argv[1] ?? '';
require __DIR__ . '/../plugin/src/AppException.php';
require __DIR__ . '/../plugin/src/Crypto.php';
require str_starts_with($worker, '--legacy-') ? __DIR__ . '/fixtures/StoreSchema1.php' : __DIR__ . '/../plugin/src/Store.php';
use UcrmOidc\{AppException,Crypto,Store};

function check(string $name, bool $condition): void {
    global $checks;
    $checks[] = ['name' => $name, 'passed' => $condition];
    if (!$condition) { throw new RuntimeException('assertion_failed'); }
}
function denied(string $name, callable $action, ?string $code = null): void {
    try { $action(); } catch (Throwable $error) {
        check($name, $code === null || ($error->safeCode ?? null) === $code); return;
    }
    check($name, false);
}
function openRaw(string $dir): PDO {
    $db = new PDO('sqlite:' . $dir . '/state.sqlite', null, null,
        [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC]);
    $db->exec('PRAGMA busy_timeout=5000; PRAGMA foreign_keys=ON'); return $db;
}
function snapshot(string $dir): array {
    $db = openRaw($dir); $result = [];
    foreach (['settings','flows','bindings','sessions','cache','rates','audit'] as $table) {
        $result[$table] = ['columns' => $db->query('PRAGMA table_info(' . $table . ')')->fetchAll(),
            'rows' => $db->query('SELECT * FROM ' . $table . ' ORDER BY 1')->fetchAll()];
    }
    $result['meta'] = $db->query("SELECT * FROM meta WHERE key NOT IN ('schema','logout_legacy_cleanup') ORDER BY key")->fetchAll();
    return $result;
}
function schema(string $dir): array {
    return openRaw($dir)->query('SELECT name,type,sql FROM sqlite_master ORDER BY name')->fetchAll();
}
function directory(): string {
    $dir = '/tmp/oidc-migration-' . Crypto::random();
    if (!mkdir($dir, 0700) || file_put_contents($dir . '/key', Crypto::random()) !== 64) { throw new RuntimeException('fixture_failed'); }
    chmod($dir . '/key', 0600); return $dir;
}
function startWorker(string $mode, string $dir, ?string $barrier = null): array {
    $command = [PHP_BINARY, __FILE__, $mode, $dir]; if ($barrier !== null) { $command[] = $barrier; }
    $process = proc_open($command, [0 => ['pipe','r'], 1 => ['pipe','w'], 2 => ['pipe','w']], $pipes);
    if (!is_resource($process)) { throw new RuntimeException('worker_failed'); }
    fclose($pipes[0]); return ['process' => $process, 'pipes' => $pipes];
}
function finishWorker(array $worker): array {
    $out = stream_get_contents($worker['pipes'][1]); $err = stream_get_contents($worker['pipes'][2]);
    fclose($worker['pipes'][1]); fclose($worker['pipes'][2]); $exit = proc_close($worker['process']);
    if ($exit !== 0 || $err !== '') { throw new RuntimeException('worker_failed'); }
    return json_decode($out, true, 16, JSON_THROW_ON_ERROR);
}
function waitFor(string $file): void {
    $end = hrtime(true) + 10_000_000_000;
    while (!is_file($file)) { if (hrtime(true) > $end) { throw new RuntimeException('barrier_timeout'); } usleep(10000); }
}
function legacyFixture(): string {
    $dir = directory();
    if ((finishWorker(startWorker('--legacy-create', $dir))['schema'] ?? null) !== '1') { throw new RuntimeException('legacy_fixture_failed'); }
    return $dir;
}
function populate(Store $store, Crypto $crypto): void {
    $store->run('UPDATE settings SET provider_revision=7,credential_revision=9,config_json=?,secret_enc=? WHERE id=1',
        ['{"issuer":"https://synthetic.example","clientId":"old-client"}', $crypto->seal(['secret' => 'synthetic-only'], 'provider-secret:9')]);
    $store->run('INSERT INTO meta VALUES(?,?)', ['synthetic-retained-marker','unchanged']);
    foreach (['active' => 1, 'tombstone' => 0] as $id => $active) {
        $store->run('INSERT INTO bindings VALUES(?,?,?,?,?,?,?,?,?,?)', [$id, 'https://synthetic.example',
            $crypto->digest('subject', $id), 'native-' . $id, $id, $active, 4,
            $crypto->seal(['subject' => $id], 'binding:' . $id), 100, 200]);
    }
    foreach (['session' => 0, 'pending' => 1] as $id => $pending) {
        $store->run('INSERT INTO sessions VALUES(?,?,?,?,?,?,?,?)', [$id,'active','native-active',300,250,
            $crypto->seal(['kind' => 'session', 'receipt' => 'synthetic-' . $id], 'session:' . $id),$pending,3000000]);
    }
    foreach (['started','verifying','verified','mfa','issuing','uncertain','cleanup','done'] as $status) {
        $id = 'flow-' . $status;
        $store->run('INSERT INTO flows VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)', [$id,'state-' . $id,'browser-' . $id,
            $status,301,300001,7,9,'native-revision','native-epoch',
            $crypto->seal(['challenge' => ['receipt' => 'synthetic-' . $status]], 'flow:' . $id),2,'active']);
    }
    $store->run('INSERT INTO cache VALUES(?,?,?)', ['retained-cache','{"synthetic":true}',400]);
    $store->run('INSERT INTO rates VALUES(?,?,?)', ['retained-rate',300,2]);
    $store->audit('synthetic.migration','synthetic-actor','synthetic-object','pending',300);
}

if ($worker !== '') {
    try {
        $dir = $argv[2];
        if ($worker === '--migrate') { touch($argv[3] . '.' . getmypid()); waitFor($argv[3]); }
        try { $store = new Store(new Crypto($dir . '/key'), $dir . '/state.sqlite'); }
        catch (AppException $error) {
            if ($worker === '--legacy-open') { echo json_encode(['denied' => $error->safeCode]); exit(0); }
            throw $error;
        }
        if ($worker === '--legacy-create') { populate($store, new Crypto($dir . '/key')); }
        echo json_encode(['schema' => $store->one('SELECT value FROM meta WHERE key=?', ['schema'])['value']]); exit(0);
    } catch (Throwable) { echo '{"workerFailed":true}'; exit(1); }
}

$checks = [];
try {
    $fresh = directory(); $freshCrypto = new Crypto($fresh . '/key'); $freshStore = new Store($freshCrypto, $fresh . '/state.sqlite');
    check('fresh database selects schema2', $freshStore->one("SELECT value FROM meta WHERE key='schema'")['value'] === '2');
    check('fresh database has no legacy cleanup requirement', $freshStore->one("SELECT value FROM meta WHERE key='logout_legacy_cleanup'")['value'] === 'complete');
    foreach (['session_context','flow_context','logout_events','logout_fences','logout_targets'] as $table) {
        check('fresh empty ' . $table, (int) $freshStore->one('SELECT COUNT(*) AS n FROM ' . $table)['n'] === 0);
    }
    check('database stays private0600', (fileperms($fresh . '/state.sqlite') & 0777) === 0600);

    $dir = legacyFixture(); $before = snapshot($dir); $crypto = new Crypto($dir . '/key');
    $store = new Store($crypto, $dir . '/state.sqlite');
    check('populated legacy upgrade selects schema2', $store->one("SELECT value FROM meta WHERE key='schema'")['value'] === '2');
    check('legacy upgrade requires application cleanup', $store->one("SELECT value FROM meta WHERE key='logout_legacy_cleanup'")['value'] === 'required');
    check('every legacy column row ciphertext key and tombstone is unchanged', snapshot($dir) === $before);
    check('legacy cleanup receipts decrypt with original key and AAD', $crypto->open($store->one("SELECT artifact_enc FROM sessions WHERE id='pending'")['artifact_enc'], 'session:pending')['receipt'] === 'synthetic-pending');
    check('legacy client and sid are never invented', (int) $store->one('SELECT COUNT(*) AS n FROM session_context')['n'] === 0 && (int) $store->one('SELECT COUNT(*) AS n FROM flow_context')['n'] === 0);
    check('old022 actual Store refuses schema2', (finishWorker(startWorker('--legacy-open', $dir))['denied'] ?? null) === 'SCHEMA_UNSUPPORTED');
    $store->run("UPDATE meta SET value='complete' WHERE key='logout_legacy_cleanup'");
    $reopened = new Store($crypto, $dir . '/state.sqlite');
    check('reopen preserves completed cleanup marker', $reopened->one("SELECT value FROM meta WHERE key='logout_legacy_cleanup'")['value'] === 'complete');
    check('reopen is idempotent for all legacy data', snapshot($dir) === $before);
    $reopened->run("DELETE FROM meta WHERE key='logout_legacy_cleanup'");
    $reopened = new Store($crypto, $dir . '/state.sqlite');
    check('missing marker on existing schema2 fails closed', $reopened->one("SELECT value FROM meta WHERE key='logout_legacy_cleanup'")['value'] === 'required');

    $wrongDir = legacyFixture(); $wrongBefore = snapshot($wrongDir); $wrongSchema = schema($wrongDir);
    denied('wrong key refuses migration', fn() => new Store($freshCrypto, $wrongDir . '/state.sqlite'), 'KEY_MISMATCH');
    check('wrong key leaves old schema and rows unchanged', snapshot($wrongDir) === $wrongBefore && schema($wrongDir) === $wrongSchema
        && openRaw($wrongDir)->query("SELECT value FROM meta WHERE key='schema'")->fetchColumn() === '1');
    $unknown = legacyFixture(); openRaw($unknown)->exec("UPDATE meta SET value='3' WHERE key='schema'");
    $unknownBefore = snapshot($unknown); $unknownSchema = schema($unknown);
    denied('future schema refuses migration', fn() => new Store(new Crypto($unknown . '/key'), $unknown . '/state.sqlite'), 'SCHEMA_UNSUPPORTED');
    check('future schema rows and definitions unchanged', snapshot($unknown) === $unknownBefore && schema($unknown) === $unknownSchema);

    $abort = legacyFixture(); $abortDb = openRaw($abort);
    $abortDb->exec("CREATE TRIGGER synthetic_abort BEFORE UPDATE OF value ON meta WHEN OLD.key='schema' BEGIN SELECT RAISE(ABORT,'synthetic_failure'); END");
    $abortBefore = snapshot($abort); $abortSchema = schema($abort);
    denied('failure at final schema promotion is reported', fn() => new Store(new Crypto($abort . '/key'), $abort . '/state.sqlite'), 'STATE_UNAVAILABLE');
    check('failed migration rolls back all side tables indexes marker and old data', snapshot($abort) === $abortBefore && schema($abort) === $abortSchema
        && $abortDb->query("SELECT COUNT(*) FROM meta WHERE key='logout_legacy_cleanup'")->fetchColumn() === 0);
    $abortDb->exec('DROP TRIGGER synthetic_abort');
    $retried = new Store(new Crypto($abort . '/key'), $abort . '/state.sqlite');
    check('same database retries successfully after rolled back failure', $retried->one("SELECT value FROM meta WHERE key='schema'")['value'] === '2' && snapshot($abort) === $abortBefore);

    $concurrent = legacyFixture(); $concurrentBefore = snapshot($concurrent); $barrier = $concurrent . '/go';
    $workers = [startWorker('--migrate', $concurrent, $barrier),startWorker('--migrate', $concurrent, $barrier)];
    foreach ($workers as $child) { $status = proc_get_status($child['process']); waitFor($barrier . '.' . $status['pid']); }
    touch($barrier); $results = array_map(finishWorker(...), $workers);
    check('two concurrent real processes both open complete schema2', $results === [['schema' => '2'],['schema' => '2']]);
    check('concurrent migration preserves old data exactly once', snapshot($concurrent) === $concurrentBefore
        && openRaw($concurrent)->query("SELECT COUNT(*) FROM meta WHERE key='logout_legacy_cleanup' AND value='required'")->fetchColumn() === 1);

    $store->run('INSERT INTO session_context VALUES(?,?,?,?,?,?,?)', ['session','issuer','client','subject','sid',300,301]);
    $store->run('INSERT INTO session_context VALUES(?,?,?,?,?,?,?)', ['pending','issuer','client','subject',null,300,301]);
    $store->run('INSERT INTO flow_context VALUES(?,?,?,?,?,?,?)', ['flow-verifying','issuer','client',0,null,null,null]);
    denied('orphan session context rejected', fn() => $store->run('INSERT INTO session_context VALUES(?,?,?,?,?,?,?)', ['missing','issuer','client','subject',null,300,301]));
    denied('orphan flow context rejected', fn() => $store->run('INSERT INTO flow_context VALUES(?,?,?,?,?,?,?)', ['missing','issuer','client',0,null,null,null]));
    $store->run("DELETE FROM sessions WHERE id='session'"); $store->run("DELETE FROM flows WHERE id='flow-verifying'");
    check('native ledger deletion cascades only its context', $store->one("SELECT session_id FROM session_context WHERE session_id='session'") === null
        && $store->one("SELECT session_id FROM session_context WHERE session_id='pending'") !== null);
    check('flow deletion cascades its context', $store->one("SELECT flow_id FROM flow_context WHERE flow_id='flow-verifying'") === null);

    $eventSql = 'INSERT INTO logout_events(id,issuer,client_id,jti_hash,subject_hash,sid_hash,issued_at,received_at,expires_at,replay_until) VALUES(?,?,?,?,?,?,?,?,?,?)';
    $store->run($eventSql, ['event1','issuer','client','jti','subject','sid',10,11,20,100]);
    $sequence = (int) $store->one("SELECT sequence FROM logout_events WHERE id='event1'")['sequence'];
    denied('same scoped jti cannot select a second event', fn() => $store->run($eventSql, ['duplicate','issuer','client','jti','subject','sid',30,31,40,120]));
    $store->run($eventSql, ['other-client','issuer','other','jti','subject','sid',10,11,20,100]);
    check('different registration may use same jti', (int) $store->one('SELECT COUNT(*) AS n FROM logout_events')['n'] === 2);
    $store->run('INSERT INTO logout_fences VALUES(?,?,?,?,?,?,?,?)', ['issuer','client','subject','subject',$sequence,10,11,100]);
    $store->run('INSERT INTO logout_targets(event_id,target_kind,target_id) VALUES(?,?,?)', ['event1','session','pending']);
    check('new target has durable fairness cursor zero', $store->one("SELECT last_attempt FROM logout_targets WHERE event_id='event1'")['last_attempt'] === 0);
    $store->run("UPDATE logout_targets SET last_attempt=7 WHERE event_id='event1'");
    $cursorStore = new Store($crypto, $dir . '/state.sqlite');
    check('target retry cursor survives reopening unchanged', $cursorStore->one("SELECT last_attempt FROM logout_targets WHERE event_id='event1'")['last_attempt'] === 7);
    check('target fairness index supports event status and cursor selection', array_column($cursorStore->all('PRAGMA index_info(logout_targets_fair)'), 'name')
        === ['event_id','status','last_attempt','target_kind','target_id']);
    check('global retry watermark uses an indexed search', str_contains(json_encode($cursorStore->all('EXPLAIN QUERY PLAN SELECT MAX(last_attempt) FROM logout_targets')), 'logout_targets_attempt'));
    denied('invalid target kind rejected', fn() => $store->run('INSERT INTO logout_targets(event_id,target_kind,target_id) VALUES(?,?,?)', ['event1','account','pending']));
    denied('invalid target state rejected', fn() => $store->run("UPDATE logout_targets SET status='revoked' WHERE event_id='event1'"));
    denied('target requires durable event', fn() => $store->run('INSERT INTO logout_targets(event_id,target_kind,target_id) VALUES(?,?,?)', ['missing','flow','flow-issuing']));
    denied('event fence and target claim rolls back together', fn() => $store->tx(function () use ($store, $eventSql): void {
        $store->run($eventSql, ['rollback','issuer','client','rollback-jti','subject',null,10,11,20,100]);
        $store->run('INSERT INTO logout_targets(event_id,target_kind,target_id) VALUES(?,?,?)', ['rollback','flow','flow-issuing']);
        $store->run("UPDATE logout_fences SET cutoff_iat=999 WHERE issuer='issuer'");
        throw new RuntimeException('synthetic_failure');
    }));
    check('failed event claim leaves no partial work or cutoff', $store->one("SELECT id FROM logout_events WHERE id='rollback'") === null
        && $store->one("SELECT event_id FROM logout_targets WHERE event_id='rollback'") === null
        && $store->one("SELECT cutoff_iat FROM logout_fences WHERE issuer='issuer'")['cutoff_iat'] === 10);
    $priorSequence = (int) $store->one("SELECT seq FROM sqlite_sequence WHERE name='logout_events'")['seq'];
    $store->run('DELETE FROM logout_events');
    check('event removal cascades targets without erasing independent fence', $store->one('SELECT event_id FROM logout_targets') === null
        && $store->one('SELECT scope_hash FROM logout_fences') !== null);
    check('monotonic watermark survives removal of every event', (int) $store->one("SELECT seq FROM sqlite_sequence WHERE name='logout_events'")['seq'] === $priorSequence);
    $store->run($eventSql, ['new-event','issuer','client','new-jti','subject',null,30,31,40,120]);
    check('new event never reuses a retired sequence', (int) $store->one("SELECT sequence FROM logout_events WHERE id='new-event'")['sequence'] > $priorSequence);
    check('foreign key integrity remains valid', $store->all('PRAGMA foreign_key_check') === []);
    check('sqlite integrity remains valid', $store->one('PRAGMA integrity_check')['integrity_check'] === 'ok');
    $complete = true;
} catch (Throwable $error) {
    $complete = false;
    $checks[] = ['name' => 'suite completion', 'passed' => false, 'safeCode' => $error instanceof AppException ? $error->safeCode : 'TEST_FAILED'];
}
echo json_encode(['phpVersion' => PHP_VERSION,'checks' => $checks,'complete' => $complete,
    'syntheticOnly' => true,'nativeCalls' => 0,'legacySource' => '80c680b1d5dae71793279de5355c99b46f8bd971'], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n";
exit($complete ? 0 : 1);
