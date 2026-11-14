<?php
declare(strict_types=1);
namespace UcrmOidc;

use Facile\JoseVerifier\JWK\JwksProviderInterface;
use Facile\JoseVerifier\IdTokenVerifierInterface;
use Facile\OpenIDClient\Client\ClientInterface as OidcClient;
use Facile\OpenIDClient\Client\ClientBuilder;
use Facile\OpenIDClient\Client\Metadata\ClientMetadata;
use Facile\OpenIDClient\Issuer\Issuer;
use Facile\OpenIDClient\Issuer\Metadata\IssuerMetadata;
use Facile\OpenIDClient\Token\IdTokenVerifierBuilderInterface;
use Facile\OpenIDClient\Service\Builder\AuthorizationServiceBuilder;
use Facile\OpenIDClient\Service\Builder\UserInfoServiceBuilder;
use Facile\OpenIDClient\Session\AuthSession;
use Nyholm\Psr7\Factory\Psr17Factory;
use Psr\Http\Client\ClientInterface;
use Jose\Component\Core\{AlgorithmManager, JWKSet};
use Jose\Component\Signature\{JWS, JWSVerifier};
use Jose\Component\Signature\Algorithm\RS256;
use Jose\Component\Signature\Serializer\CompactSerializer;

/** Required integration policy around the maintained JOSE implementation. */
final class StrictIdTokenVerifierBuilder implements IdTokenVerifierBuilderInterface
{
    public function build(OidcClient $client): IdTokenVerifierInterface
    {
        return \Facile\JoseVerifier\Builder\IdTokenVerifierBuilder::create(
            $client->getIssuer()->getMetadata()->toArray(), $client->getMetadata()->toArray())
            ->withJwksProvider($client->getIssuer()->getJwksProvider())
            ->withClientJwksProvider($client->getJwksProvider())
            ->withExpectedAzp($client->getMetadata()->getClientId())
            ->withClockTolerance(30)->build();
    }
}

final class CachedJwks implements JwksProviderInterface
{
    private ?array $keys = null;
    private bool $reloaded = false;
    public function __construct(private readonly Store $store, private readonly ClientInterface $http,
        private readonly string $url, private readonly \Closure $clock) {}

    public function getJwks(): array
    {
        if ($this->keys !== null) { return $this->keys; }
        $now = ($this->clock)(); $key = 'jwks:' . hash('sha256', $this->url);
        $cached = $this->store->cached($key, $now);
        if ($cached !== null) { return $this->keys = $cached; }
        $value = HttpClient::json($this->http, $this->url);
        if (!is_array($value['keys'] ?? null) || !array_is_list($value['keys']) || count($value['keys']) < 1 || count($value['keys']) > 32) { throw new AppException('INVALID_JWKS', 502); }
        $usable = []; $ids = [];
        foreach ($value['keys'] as $jwk) {
            if (!is_array($jwk) || ($jwk['kty'] ?? '') !== 'RSA' || (($jwk['use'] ?? 'sig') !== 'sig')
                || (($jwk['alg'] ?? 'RS256') !== 'RS256')) { continue; }
            if (!is_string($jwk['kid'] ?? null) || $jwk['kid'] === '' || strlen($jwk['kid']) > 256 || isset($ids[$jwk['kid']])
                || !is_string($jwk['n'] ?? null) || !preg_match('/\A[A-Za-z0-9_-]{342,1400}\z/D', $jwk['n'])
                || !is_string($jwk['e'] ?? null) || !preg_match('/\A[A-Za-z0-9_-]{1,16}\z/D', $jwk['e'])
                || array_intersect(array_keys($jwk), ['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth'])) { throw new AppException('INVALID_JWKS', 502); }
            $modulus = self::integer($jwk['n']); $exponent = self::integer($jwk['e']);
            $bits = (strlen($modulus) - 1) * 8 + strlen(decbin(ord($modulus[0])));
            if ($bits < 2048 || $bits > 8192 || strlen($exponent) > 4
                || (strlen($exponent) === 1 && ord($exponent[0]) < 3) || (ord($exponent[strlen($exponent) - 1]) & 1) !== 1) { throw new AppException('INVALID_JWKS', 502); }
            if (isset($jwk['key_ops']) && (!is_array($jwk['key_ops']) || !in_array('verify', $jwk['key_ops'], true))) { continue; }
            $ids[$jwk['kid']] = true;
            $usable[] = array_intersect_key($jwk, array_flip(['kty', 'kid', 'n', 'e', 'alg', 'use', 'key_ops']));
        }
        if (!$usable) { throw new AppException('INVALID_JWKS', 502); }
        $this->keys = ['keys' => $usable]; $this->store->cache($key, $this->keys, $now); return $this->keys;
    }
    private static function integer(string $value): string
    {
        $decoded = base64_decode(strtr($value, '-_', '+/'), true);
        if ($decoded === false || $decoded === '' || $decoded[0] === "\0"
            || rtrim(strtr(base64_encode($decoded), '+/', '-_'), '=') !== $value) { throw new AppException('INVALID_JWKS', 502); }
        return $decoded;
    }
    public function reload(): JwksProviderInterface
    {
        if ($this->reloaded) { throw new AppException('KEY_REFRESH_LIMITED', 429); }
        $this->reloaded = true;
        $this->store->rate('jwks-refresh:' . hash('sha256', $this->url), 1, 30, ($this->clock)());
        $this->store->run('DELETE FROM cache WHERE cache_key=?', ['jwks:' . hash('sha256', $this->url)]);
        $this->keys = null; return $this;
    }
}

final class Oidc
{
    public const LOGOUT_EVENT = 'http://schemas.openid.net/event/backchannel-logout';
    // Replay custody lasts 32 days. A single signed delivery must expire much
    // sooner; a provider can renew delivery times while retaining its jti.
    public const LOGOUT_MAX_LIFETIME = 86400;
    private readonly \Closure $clock;
    private readonly \Closure $httpFactory;
    public function __construct(private readonly Store $store, ?callable $httpFactory = null, ?callable $clock = null)
    {
        $this->clock = \Closure::fromCallable($clock ?? time(...));
        $this->httpFactory = \Closure::fromCallable($httpFactory ?? static fn(array $origins): ClientInterface => new HttpClient($origins));
    }

    public function discovery(array $settings): array
    {
        $key = 'discovery:' . hash('sha256', json_encode([$settings['issuer'], $settings['discoveryUrl'], $settings['endpointOrigins']], JSON_THROW_ON_ERROR));
        $now = ($this->clock)();
        $metadata = $this->store->cached($key, $now);
        $fetched = $metadata === null;
        if ($fetched) {
            $this->store->rate('discovery-fetch', 20, 60, $now);
            $metadata = HttpClient::json($this->http($settings), $settings['discoveryUrl']);
        }
        if (($metadata['issuer'] ?? null) !== $settings['issuer']) { throw new AppException('ISSUER_MISMATCH', 502); }
        foreach (['authorization_endpoint', 'token_endpoint', 'jwks_uri'] as $field) {
            $this->endpoint($metadata[$field] ?? null, $settings);
        }
        if ($settings['emailSource'] === 'userinfo') { $this->endpoint($metadata['userinfo_endpoint'] ?? null, $settings); }
        elseif (isset($metadata['userinfo_endpoint'])) { $this->endpoint($metadata['userinfo_endpoint'], $settings); }
        foreach ([['response_types_supported', 'code'], ['id_token_signing_alg_values_supported', 'RS256'],
            ['code_challenge_methods_supported', 'S256']] as [$keyName, $required]) {
            if (!is_array($metadata[$keyName] ?? null) || !in_array($required, $metadata[$keyName], true)) { throw new AppException('PROVIDER_CAPABILITY_UNSUPPORTED', 502); }
        }
        if (!in_array($settings['clientAuthMethod'], $metadata['token_endpoint_auth_methods_supported'] ?? ['client_secret_basic'], true)) { throw new AppException('CLIENT_AUTH_UNSUPPORTED', 502); }
        // Project only supported metadata; do not activate optional discovery extensions.
        $metadata = array_intersect_key($metadata, array_flip(['issuer', 'authorization_endpoint', 'token_endpoint',
            'jwks_uri', 'userinfo_endpoint', 'response_types_supported', 'id_token_signing_alg_values_supported',
            'code_challenge_methods_supported', 'token_endpoint_auth_methods_supported']));
        if ($fetched) { $this->store->cache($key, $metadata, $now); }
        return $metadata;
    }
    private function endpoint(mixed $url, array $settings): void
    {
        if (!is_string($url) || !in_array(Config::origin($url), Config::origins($settings), true)) { throw new AppException('ENDPOINT_ORIGIN_DENIED', 502); }
    }
    private function http(array $settings): ClientInterface
    {
        return new ProviderResponseClient(($this->httpFactory)(Config::origins($settings)));
    }
    private function client(array $settings, ?string $secret): array
    {
        $metadata = $this->discovery($settings);
        $http = $this->http($settings);
        $clientMetadata = ['client_id' => $settings['clientId'], 'redirect_uris' => [Config::callback($settings)],
            'response_types' => ['code'], 'grant_types' => ['authorization_code'],
            'token_endpoint_auth_method' => $settings['clientAuthMethod'], 'id_token_signed_response_alg' => 'RS256'];
        if ($settings['clientAuthMethod'] !== 'none') {
            if ($secret === null || $secret === '') { throw new AppException('CLIENT_SECRET_REQUIRED', 503); }
            $clientMetadata['client_secret'] = $secret;
        }
        $issuer = new Issuer(IssuerMetadata::fromArray($metadata), new CachedJwks($this->store, $http, $metadata['jwks_uri'], $this->clock));
        $client = (new ClientBuilder())->setIssuer($issuer)->setClientMetadata(ClientMetadata::fromArray($clientMetadata))->setHttpClient($http)->build();
        $service = (new AuthorizationServiceBuilder())->setHttpClient($http)->setRequestFactory(new Psr17Factory())
            ->setIdTokenVerifierBuilder(new StrictIdTokenVerifierBuilder())->build();
        return [$client, $service, $http];
    }
    public function authorization(array $settings, ?string $secret, array $flow): string
    {
        try {
            [$client, $service] = $this->client($settings, $secret);
            return $service->getAuthorizationUri($client, [
                'scope' => $settings['scopes'], 'response_type' => 'code', 'response_mode' => 'query',
                'state' => $flow['state'], 'nonce' => $flow['nonce'],
                'code_challenge' => rtrim(strtr(base64_encode(hash('sha256', $flow['code_verifier'], true)), '+/', '-_'), '='),
                'code_challenge_method' => 'S256', 'max_age' => $flow['maxAge'],
            ]);
        } catch (AppException $error) { throw $error; }
        catch (\Throwable) { throw new AppException('PROVIDER_UNAVAILABLE', 502); }
    }
    public function verify(array $settings, ?string $secret, array $flow, array $parameters): array
    {
        try {
            if (!is_string($parameters['code'] ?? null) || $parameters['code'] === '' || strlen($parameters['code']) > 2048
                || !is_string($parameters['state'] ?? null) || !hash_equals($flow['state'], $parameters['state'])
                || isset($parameters['error']) || isset($parameters['id_token']) || isset($parameters['access_token'])
                || (isset($parameters['iss']) && $parameters['iss'] !== $settings['issuer'])) { throw new AppException('AUTHENTICATION_DENIED', 403); }
            [$client, $service, $http] = $this->client($settings, $secret);
            $tokens = $service->callback($client, ['code' => $parameters['code'], 'state' => $parameters['state']],
                Config::callback($settings), AuthSession::fromArray($flow), $flow['maxAge']);
            if ($tokens->getIdToken() === null || strlen($tokens->getIdToken()) > 32768) { throw new AppException('AUTHENTICATION_DENIED', 403); }
            $claims = $tokens->claims();
            self::validateClaims($claims, $settings, $flow, ($this->clock)());
            $attributes = $claims;
            if ($settings['emailSource'] === 'userinfo') {
                if (!is_string($tokens->getAccessToken()) || strlen($tokens->getAccessToken()) > 8192
                    || strcasecmp($tokens->getTokenType() ?? '', 'Bearer') !== 0) { throw new AppException('AUTHENTICATION_DENIED', 403); }
                $attributes = (new UserInfoServiceBuilder())->setHttpClient($http)->setRequestFactory(new Psr17Factory())->build()->getUserInfo($client, $tokens);
                if (($attributes['sub'] ?? null) !== $claims['sub']) { throw new AppException('SUBJECT_MISMATCH', 403); }
            }
            $email = Config::claim($attributes, $settings['emailClaim']);
            if (!is_string($email) || strlen($email) > 320 || !filter_var($email, FILTER_VALIDATE_EMAIL)) { $email = null; }
            return ['issuer' => $settings['issuer'], 'clientId' => $settings['clientId'],
                'subject' => $claims['sub'], 'sid' => $claims['sid'] ?? null, 'issuedAt' => $claims['iat'], 'email' => $email,
                'emailVerified' => Config::claim($attributes, $settings['emailVerifiedClaim']) === true,
                'authTime' => $claims['auth_time'] ?? null];
        } catch (AppException $error) { throw $error; }
        catch (\Throwable) { throw new AppException('AUTHENTICATION_DENIED', 403); }
    }
    /** Authenticate a provider notification without a browser or client secret. */
    public function verifyLogout(array $settings, #[\SensitiveParameter] string $token): array
    {
        try {
            if (strlen($token) > 32768 || !preg_match('/\A[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\z/D', $token)) {
                throw new AppException('LOGOUT_INVALID', 400);
            }
            $jws = (new CompactSerializer())->unserialize($token);
            $header = $jws->getSignature(0)->getProtectedHeader();
            if (($header['alg'] ?? null) !== 'RS256' || array_key_exists('crit', $header) || array_key_exists('b64', $header)
                || (array_key_exists('kid', $header) && !self::identifier($header['kid'], 256))
                || (array_key_exists('typ', $header) && (!is_string($header['typ'])
                    || !in_array(strtolower($header['typ']), ['logout+jwt', 'application/logout+jwt', 'jwt', 'application/jwt'], true)))) {
                throw new AppException('LOGOUT_INVALID', 400);
            }
            // Object decoding is deliberate: [] is not the required events:{}.
            $claims = json_decode($jws->getPayload() ?? '', false, 32, JSON_THROW_ON_ERROR);
            self::logoutClaims($claims, $settings, ($this->clock)());
        } catch (AppException $error) { throw $error; }
        catch (\Throwable) { throw new AppException('LOGOUT_INVALID', 400); }

        try {
            // All network locations come from configured, origin-checked
            // discovery. Untrusted iss/jku/x5u/jwk headers never select a key.
            $metadata = $this->discovery($settings);
            $keys = new CachedJwks($this->store, $this->http($settings), $metadata['jwks_uri'], $this->clock);
            $valid = self::logoutSignature($jws, $keys->getJwks(), $header['kid'] ?? null);
            if (!$valid) {
                try { $keys->reload(); }
                catch (AppException $error) {
                    if (in_array($error->safeCode, ['KEY_REFRESH_LIMITED', 'RATE_LIMITED'], true)) {
                        throw new AppException('LOGOUT_INVALID', 400);
                    }
                    throw $error;
                }
                $valid = self::logoutSignature($jws, $keys->getJwks(), $header['kid'] ?? null);
            }
            if (!$valid) { throw new AppException('LOGOUT_INVALID', 400); }
            return self::logoutClaims($claims, $settings, ($this->clock)());
        } catch (AppException $error) {
            if ($error->safeCode === 'LOGOUT_INVALID') { throw $error; }
            throw new AppException('LOGOUT_UNAVAILABLE', 503);
        } catch (\Throwable) { throw new AppException('LOGOUT_UNAVAILABLE', 503); }
    }
    private static function logoutSignature(JWS $jws, array $keys, ?string $kid): bool
    {
        // JWSVerifier tries every supplied key; apply kid selection explicitly.
        $selected = array_values(array_filter($keys['keys'], static fn(array $key): bool => $kid === null || $key['kid'] === $kid));
        if (!$selected) { return false; }
        return (new JWSVerifier(new AlgorithmManager([new RS256()])))
            ->verifyWithKeySet($jws, JWKSet::createFromKeyData(['keys' => $selected]), 0);
    }
    private static function identifier(mixed $value, int $limit): bool
    {
        return is_string($value) && $value !== '' && strlen($value) <= $limit && !preg_match('/[\x00-\x1f\x7f]/', $value);
    }
    private static function logoutClaims(mixed $claims, array $settings, int $now): array
    {
        if (!$claims instanceof \stdClass) { throw new AppException('LOGOUT_INVALID', 400); }
        $aud = $claims->aud ?? null;
        if (is_string($aud)) { $aud = [$aud]; }
        $validAud = is_array($aud) && array_is_list($aud) && count($aud) > 0 && count($aud) <= 16;
        if ($validAud) { foreach ($aud as $value) { $validAud = $validAud && self::identifier($value, 1024); } }
        $subPresent = property_exists($claims, 'sub'); $sidPresent = property_exists($claims, 'sid');
        $events = $claims->events ?? null;
        if (($claims->iss ?? null) !== $settings['issuer'] || !$validAud || !in_array($settings['clientId'], $aud, true)
            || (count($aud) > 1 && !property_exists($claims, 'azp'))
            || (property_exists($claims, 'azp') && $claims->azp !== $settings['clientId'])
            || (!$subPresent && !$sidPresent) || ($subPresent && !self::identifier($claims->sub, 255))
            || ($sidPresent && !self::identifier($claims->sid, 1024)) || !self::identifier($claims->jti ?? null, 255)
            || property_exists($claims, 'nonce') || !$events instanceof \stdClass
            || !property_exists($events, self::LOGOUT_EVENT) || !$events->{self::LOGOUT_EVENT} instanceof \stdClass
            || !is_int($claims->iat ?? null) || $claims->iat < 1 || $claims->iat > $now + 30
            || $claims->iat < $now - self::LOGOUT_MAX_LIFETIME - 30
            || !is_int($claims->exp ?? null) || $claims->exp <= $now - 30 || $claims->exp <= $claims->iat
            || $claims->exp - $claims->iat > self::LOGOUT_MAX_LIFETIME
            || (property_exists($claims, 'nbf') && (!is_int($claims->nbf) || $claims->nbf > $now + 30))) {
            throw new AppException('LOGOUT_INVALID', 400);
        }
        return ['issuer' => $settings['issuer'], 'clientId' => $settings['clientId'], 'subject' => $claims->sub ?? null,
            'sid' => $claims->sid ?? null, 'issuedAt' => $claims->iat, 'expiresAt' => $claims->exp, 'jti' => $claims->jti];
    }
    /** Runs only after signature verification; exported for real-signature tests. */
    public static function validateClaims(array $claims, array $settings, array $flow, int $now): void
    {
        $aud = $claims['aud'] ?? null;
        if (is_string($aud)) { $aud = [$aud]; }
        $validAud = is_array($aud) && array_is_list($aud) && count($aud) > 0 && count($aud) <= 16;
        if ($validAud) { foreach ($aud as $value) { $validAud = $validAud && is_string($value) && $value !== ''; } }
        if (($claims['iss'] ?? null) !== $settings['issuer'] || !is_string($claims['sub'] ?? null) || $claims['sub'] === ''
            || strlen($claims['sub']) > 255 || preg_match('/[\x00-\x1f\x7f]/', $claims['sub'])
            || (array_key_exists('sid', $claims) && !self::identifier($claims['sid'], 1024))
            || !$validAud || !in_array($settings['clientId'], $aud, true)
            || (count($aud) > 1 && !isset($claims['azp']))
            || (isset($claims['azp']) && $claims['azp'] !== $settings['clientId'])
            || !is_string($claims['nonce'] ?? null) || !hash_equals($flow['nonce'], $claims['nonce'])
            || !is_int($claims['exp'] ?? null) || $claims['exp'] <= $now - 30
            || !is_int($claims['iat'] ?? null) || $claims['iat'] > $now + 30 || $claims['iat'] > $claims['exp']
            || (isset($claims['auth_time']) && (!is_int($claims['auth_time']) || $claims['auth_time'] < 1 || $claims['auth_time'] > $now + 30))
            || ($flow['maxAge'] !== null && (!isset($claims['auth_time']) || $claims['auth_time'] < $now - $flow['maxAge'] - 30))) {
            throw new AppException('AUTHENTICATION_DENIED', 403);
        }
    }
}
