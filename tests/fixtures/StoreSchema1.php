<?php
declare(strict_types=1);
namespace UcrmOidc;

/** Fixed-path persistent state. All SQL is internal; HTTP cannot supply SQL/path. */
final class Store
{
    private \PDO $db;
    private bool $transaction = false;

    public function __construct(private readonly Crypto $crypto, string $path = '/var/lib/ucrm-oidc/state.sqlite')
    {
        $directory = dirname($path);
        if (!is_dir($directory) || is_link($directory) || is_link($path)
            || (fileperms($directory) & 0077) !== 0 || !is_writable($directory)) {
            throw new AppException('STATE_UNAVAILABLE', 503);
        }
        try {
            $oldMask = umask(0077);
            try {
                $this->db = new \PDO('sqlite:' . $path, null, null, [
                    \PDO::ATTR_ERRMODE => \PDO::ERRMODE_EXCEPTION,
                    \PDO::ATTR_DEFAULT_FETCH_MODE => \PDO::FETCH_ASSOC,
                    \PDO::ATTR_EMULATE_PREPARES => false,
                ]);
            } finally { umask($oldMask); }
            if (!chmod($path, 0600)) { throw new \RuntimeException(); }
            $this->db->exec('PRAGMA busy_timeout=5000; PRAGMA foreign_keys=ON; PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;');
            $this->tx(function (): void {
                $this->db->exec('CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)');
                $schema = $this->one('SELECT value FROM meta WHERE key=?', ['schema']);
                if ($schema !== null && $schema['value'] !== '1') { throw new AppException('SCHEMA_UNSUPPORTED', 503); }
                $keyId = $this->crypto->digest('installation', 'state-database-v1');
                $stored = $this->one('SELECT value FROM meta WHERE key=?', ['key']);
                if ($stored !== null && !hash_equals($stored['value'], $keyId)) { throw new AppException('KEY_MISMATCH', 503); }
                $this->db->exec(<<<'SQL'
CREATE TABLE IF NOT EXISTS settings (
 id INTEGER PRIMARY KEY CHECK(id=1), provider_revision INTEGER NOT NULL DEFAULT 0,
 credential_revision INTEGER NOT NULL DEFAULT 0, config_json TEXT, secret_enc TEXT);
INSERT OR IGNORE INTO settings(id) VALUES(1);
CREATE TABLE IF NOT EXISTS flows (
 id TEXT PRIMARY KEY, state_hash TEXT NOT NULL UNIQUE, browser_hash TEXT NOT NULL,
 status TEXT NOT NULL, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
 provider_revision INTEGER NOT NULL, credential_revision INTEGER NOT NULL,
 native_revision TEXT NOT NULL, epoch TEXT NOT NULL, payload TEXT NOT NULL,
 attempts INTEGER NOT NULL DEFAULT 0, binding_id TEXT);
CREATE INDEX IF NOT EXISTS flows_expiry ON flows(expires_at);
CREATE INDEX IF NOT EXISTS flows_browser ON flows(browser_hash,expires_at);
CREATE TABLE IF NOT EXISTS bindings (
 id TEXT PRIMARY KEY, issuer TEXT NOT NULL, subject_hash TEXT NOT NULL,
 native_user_id TEXT NOT NULL, username TEXT NOT NULL, active INTEGER NOT NULL CHECK(active IN(0,1)),
 version INTEGER NOT NULL, identity_enc TEXT NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL,
 UNIQUE(issuer,subject_hash));
CREATE UNIQUE INDEX IF NOT EXISTS bindings_native_active ON bindings(native_user_id) WHERE active=1;
CREATE TABLE IF NOT EXISTS sessions (
 id TEXT PRIMARY KEY, binding_id TEXT NOT NULL REFERENCES bindings(id), native_user_id TEXT NOT NULL,
 created_at INTEGER NOT NULL, auth_time INTEGER, artifact_enc TEXT NOT NULL,
 cleanup_pending INTEGER NOT NULL DEFAULT 0, expires_at INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS sessions_binding ON sessions(binding_id);
CREATE TABLE IF NOT EXISTS cache (cache_key TEXT PRIMARY KEY, value TEXT NOT NULL, expires_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS rates (rate_key TEXT PRIMARY KEY, window_start INTEGER NOT NULL, counter INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS audit (
 id INTEGER PRIMARY KEY AUTOINCREMENT, at INTEGER NOT NULL, event TEXT NOT NULL,
 actor TEXT NOT NULL, object TEXT NOT NULL, outcome TEXT NOT NULL);
SQL);
                $this->run('INSERT OR IGNORE INTO meta(key,value) VALUES(?,?)', ['schema', '1']);
                $this->run('INSERT OR IGNORE INTO meta(key,value) VALUES(?,?)', ['key', $keyId]);
            });
        } catch (AppException $error) { throw $error; }
        catch (\Throwable) { throw new AppException('STATE_UNAVAILABLE', 503); }
    }

    public function run(string $sql, array $parameters = []): int
    {
        $statement = $this->db->prepare($sql);
        $statement->execute($parameters);
        return $statement->rowCount();
    }
    public function one(string $sql, array $parameters = []): ?array
    {
        $statement = $this->db->prepare($sql); $statement->execute($parameters);
        $row = $statement->fetch(); return $row === false ? null : $row;
    }
    public function all(string $sql, array $parameters = []): array
    {
        $statement = $this->db->prepare($sql); $statement->execute($parameters); return $statement->fetchAll();
    }
    public function tx(callable $action): mixed
    {
        if ($this->transaction) { return $action(); }
        $this->db->exec('BEGIN IMMEDIATE'); $this->transaction = true;
        try { $result = $action(); $this->db->exec('COMMIT'); return $result; }
        catch (\Throwable $error) { $this->db->exec('ROLLBACK'); throw $error; }
        finally { $this->transaction = false; }
    }
    public function rate(string $key, int $limit, int $period, int $now): void
    {
        $allowed = $this->tx(function () use ($key, $limit, $period, $now): bool {
            $this->run('DELETE FROM rates WHERE window_start<?', [$now - 3600]);
            $row = $this->one('SELECT * FROM rates WHERE rate_key=?', [$key]);
            if ($row === null || $row['window_start'] <= $now - $period) {
                if ($row === null && $this->one('SELECT COUNT(*) AS n FROM rates')['n'] >= 4096) { return false; }
                $this->run('INSERT INTO rates VALUES(?,?,1) ON CONFLICT(rate_key) DO UPDATE SET window_start=excluded.window_start,counter=1', [$key, $now]);
                return true;
            }
            if ($row['counter'] >= $limit) { return false; }
            $this->run('UPDATE rates SET counter=counter+1 WHERE rate_key=?', [$key]); return true;
        });
        if (!$allowed) { throw new AppException('RATE_LIMITED', 429); }
    }
    public function cached(string $key, int $now): ?array
    {
        $row = $this->one('SELECT value FROM cache WHERE cache_key=? AND expires_at>?', [$key, $now]);
        return $row === null ? null : json_decode($row['value'], true, 32, JSON_THROW_ON_ERROR);
    }
    public function cache(string $key, array $value, int $now, int $ttl = 300): void
    {
        $this->tx(function () use ($key, $value, $now, $ttl): void {
            $this->run('DELETE FROM cache WHERE expires_at<=?', [$now]);
            $this->run('DELETE FROM cache WHERE cache_key IN (SELECT cache_key FROM cache ORDER BY expires_at DESC LIMIT -1 OFFSET 63)');
            $this->run('INSERT INTO cache VALUES(?,?,?) ON CONFLICT(cache_key) DO UPDATE SET value=excluded.value,expires_at=excluded.expires_at',
                [$key, json_encode($value, JSON_THROW_ON_ERROR), $now + $ttl]);
        });
    }
    public function audit(string $event, string $actor, string $object, string $outcome, int $now): void
    {
        foreach ([$event, $outcome] as $code) {
            if (!preg_match('/\A[a-zA-Z0-9_.:-]{1,80}\z/D', $code)) { throw new AppException('BAD_REQUEST'); }
        }
        $this->run('INSERT INTO audit(at,event,actor,object,outcome) VALUES(?,?,?,?,?)',
            [$now, $event, $this->crypto->digest('audit-actor', $actor), $this->crypto->digest('audit-object', $object), $outcome]);
        $this->run('DELETE FROM audit WHERE at<? OR id NOT IN (SELECT id FROM audit ORDER BY id DESC LIMIT 10000)', [$now - 30 * 86400]);
    }
}
