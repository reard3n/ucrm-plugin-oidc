<?php
declare(strict_types=1);
namespace UcrmOidc;

final class Crypto
{
    private readonly string $master;

    public function __construct(string $keyPath = '/run/secrets/ucrm-oidc-key')
    {
        $value = @file_get_contents($keyPath, false, null, 0, 68);
        if (!is_string($value) || !preg_match('/\A[0-9a-f]{64}(?:\r?\n)?\z/D', $value)) {
            throw new AppException('KEY_UNAVAILABLE', 503);
        }
        $this->master = hex2bin(rtrim($value, "\r\n"));
    }

    private function key(string $purpose): string
    {
        return hash_hkdf('sha256', $this->master, 32, 'ucrm-oidc:' . $purpose, '');
    }

    public function transportKey(): string { return $this->key('adapter-transport:v2'); }

    public function digest(string $purpose, string $value): string
    {
        return hash_hmac('sha256', $purpose . "\0" . $value, $this->key('identifiers:v1'));
    }

    public function seal(array $value, string $associatedData): string
    {
        $nonce = random_bytes(SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES);
        $plain = json_encode($value, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
        return base64_encode($nonce . sodium_crypto_aead_xchacha20poly1305_ietf_encrypt(
            $plain, 'ucrm-oidc:v1:' . $associatedData, $nonce, $this->key('storage:v1')
        ));
    }

    public function open(string $value, string $associatedData): array
    {
        try {
            $raw = base64_decode($value, true);
            if ($raw === false || strlen($raw) < 40 || strlen($raw) > 131072) {
                throw new \RuntimeException();
            }
            $plain = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt(substr($raw, 24),
                'ucrm-oidc:v1:' . $associatedData, substr($raw, 0, 24), $this->key('storage:v1'));
            if ($plain === false) { throw new \RuntimeException(); }
            $decoded = json_decode($plain, true, 32, JSON_THROW_ON_ERROR);
            if (!is_array($decoded)) { throw new \RuntimeException(); }
            return $decoded;
        } catch (\Throwable) {
            throw new AppException('STATE_UNAVAILABLE', 503);
        }
    }

    public function csrf(string $binding, string $purpose, int $bucket): string
    {
        return $bucket . '.' . hash_hmac('sha256', $purpose . "\0" . $binding . "\0" . $bucket, $this->key('csrf:v1'));
    }

    public static function random(): string { return bin2hex(random_bytes(32)); }
    public static function hex(mixed $value): bool { return is_string($value) && preg_match('/\A[0-9a-f]{64}\z/D', $value) === 1; }
}
