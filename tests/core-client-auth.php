<?php
declare(strict_types=1);

// The fixture supplies a signed provider and the production classes; all HTTP
// requests below are the maintained library's real PSR-7 output. No lab calls.
define('UCRM_OIDC_FIXTURES_ONLY', true);
require __DIR__ . '/core-unit.php';

use UcrmOidc\{AppException, Config, Crypto, Oidc, Store};
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\{RequestInterface, ResponseInterface};
use Nyholm\Psr7\Response;

final class ClientAuthenticationProvider implements ClientInterface
{
    public Provider $provider;
    public array $observations = [];
    public int $rejected = 0;

    public function __construct(public string $registeredMethod, public string $registeredSecret)
    {
        $this->provider = new Provider();
    }

    public function sendRequest(RequestInterface $request): ResponseInterface
    {
        if ($request->getUri()->getPath() !== '/token') {
            return $this->provider->sendRequest($request);
        }
        parse_str((string) $request->getBody(), $body);
        $authorization = $request->getHeaderLine('Authorization');
        $basic = 'Basic ' . base64_encode(urlencode('test-client') . ':' . urlencode($this->registeredSecret));
        $accepted = match ($this->registeredMethod) {
            'client_secret_basic' => hash_equals($basic, $authorization) && !array_key_exists('client_secret', $body),
            'client_secret_post' => $authorization === '' && ($body['client_id'] ?? null) === 'test-client'
                && ($body['client_secret'] ?? null) === $this->registeredSecret,
            'none' => $authorization === '' && ($body['client_id'] ?? null) === 'test-client'
                && !array_key_exists('client_secret', $body),
        };
        // Store only safe booleans. Neither test output nor errors contain the
        // request, secret, authorization header, token, or signing key.
        $this->observations[] = [
            'accepted' => $accepted,
            'post' => $request->getMethod() === 'POST',
            'form' => str_starts_with($request->getHeaderLine('Content-Type'), 'application/x-www-form-urlencoded'),
            'urlContainsNoCredentials' => $request->getUri()->getQuery() === '' && $request->getUri()->getUserInfo() === '',
            'grant' => ($body['grant_type'] ?? null) === 'authorization_code',
            'hasVerifier' => is_string($body['code_verifier'] ?? null) && strlen($body['code_verifier']) >= 43,
            'hasAuthorization' => $authorization !== '',
            'hasBodySecret' => array_key_exists('client_secret', $body),
            'hasClientId' => ($body['client_id'] ?? null) === 'test-client',
        ];
        if (!$accepted) {
            ++$this->rejected;
            return new Response(401, ['Content-Type' => 'application/json'], '{"error":"invalid_client"}');
        }
        return $this->provider->sendRequest($request);
    }
}

function authCase(string $method, ?string $sentSecret, string $registration = '', string $clientId = 'test-client'): array
{
    $directory = '/tmp/oidc-client-auth-' . Crypto::random();
    mkdir($directory, 0700);
    file_put_contents($directory . '/key', Crypto::random()); chmod($directory . '/key', 0600);
    $store = new Store(new Crypto($directory . '/key'), $directory . '/state.sqlite');
    $provider = new ClientAuthenticationProvider($registration === '' ? $method : $registration, 'synthetic client:secret/+%&= !');
    $oidc = new Oidc($store, fn() => $provider);
    $settings = Config::settings(array_replace(Config::DEFAULTS, [
        'issuer' => 'https://identity.example/oidc', 'canonicalOrigin' => 'https://crm.example',
        'clientId' => $clientId, 'clientAuthMethod' => $method,
    ]));
    $flow = ['state' => Crypto::random(), 'nonce' => Crypto::random(), 'code_verifier' => Crypto::random(), 'maxAge' => 300];
    $url = $oidc->authorization($settings, $sentSecret, $flow);
    parse_str(parse_url($url, PHP_URL_QUERY), $query);
    check($method . ' authorization exposes no client secret', !isset($query['client_secret'])
        && !isset($query['client_assertion']) && !str_contains(urldecode($url), $provider->registeredSecret)
        && ($sentSecret === null || !str_contains(urldecode($url), $sentSecret)));
    check($method . ' authorization retains PKCE and public client identifier', ($query['client_id'] ?? null) === $clientId
        && ($query['code_challenge_method'] ?? null) === 'S256'
        && ($query['code_challenge'] ?? null) === b64(hash('sha256', $flow['code_verifier'], true)));
    $code = $provider->provider->register($query);
    return compact('provider', 'oidc', 'settings', 'flow', 'code', 'sentSecret');
}

function completeAuthCase(array $case): array
{
    return $case['oidc']->verify($case['settings'], $case['sentSecret'], $case['flow'],
        ['code' => $case['code'], 'state' => $case['flow']['state']]);
}

try {
    foreach (['client_secret_basic', 'client_secret_post', 'none'] as $method) {
        $case = authCase($method, $method === 'none' ? null : 'synthetic client:secret/+%&= !');
        $identity = completeAuthCase($case);
        check($method . ' signed callback and verified UserInfo succeed', $identity['subject'] === 'subject-1'
            && $identity['email'] === 'staff@example.com' && $identity['emailVerified'] === true);
        $observations = $case['provider']->observations;
        check($method . ' exactly one credential-checked token exchange', count($observations) === 1
            && $observations[0]['accepted'] && $case['provider']->rejected === 0);
        $seen = $observations[0];
        check($method . ' token exchange is form POST with PKCE and credential-free URL',
            $seen['post'] && $seen['form'] && $seen['grant'] && $seen['hasVerifier'] && $seen['urlContainsNoCredentials']);
        check($method . ' sends only its registered authentication mechanism', match ($method) {
            'client_secret_basic' => $seen['hasAuthorization'] && !$seen['hasBodySecret'],
            'client_secret_post' => !$seen['hasAuthorization'] && $seen['hasBodySecret'] && $seen['hasClientId'],
            'none' => !$seen['hasAuthorization'] && !$seen['hasBodySecret'] && $seen['hasClientId'],
        });
    }
    foreach (['client_secret_basic', 'client_secret_post'] as $method) {
        $case = authCase($method, 'synthetic-wrong-secret');
        denied($method . ' rejects actual token endpoint invalid_client response', fn() => completeAuthCase($case), 'AUTHENTICATION_DENIED');
        check($method . ' wrong credentials cause one rejection and no retry', $case['provider']->rejected === 1
            && count($case['provider']->observations) === 1 && $case['provider']->provider->tokenRequests === 0);
    }
    $case = authCase('none', null, '', 'unregistered-client');
    denied('none rejects an unregistered public client identifier', fn() => completeAuthCase($case), 'AUTHENTICATION_DENIED');
    check('none wrong identifier has no credential fallback or retry', $case['provider']->rejected === 1
        && count($case['provider']->observations) === 1 && !$case['provider']->observations[0]['hasAuthorization']
        && !$case['provider']->observations[0]['hasBodySecret']);

    $case = authCase('none', 'synthetic-unused-secret');
    check('none ignores even an explicitly supplied unused secret', completeAuthCase($case)['emailVerified'] === true
        && !$case['provider']->observations[0]['hasAuthorization'] && !$case['provider']->observations[0]['hasBodySecret']);

    $case = authCase('none', null, 'client_secret_basic');
    denied('none requires a provider registration that permits public clients', fn() => completeAuthCase($case), 'AUTHENTICATION_DENIED');
    check('none never falls back to confidential client authentication', $case['provider']->rejected === 1
        && count($case['provider']->observations) === 1 && !$case['provider']->observations[0]['hasAuthorization']);

    echo json_encode(['suite' => 'final-package-client-auth-methods', 'phpVersion' => PHP_VERSION,
        'passed' => count($checks), 'checks' => $checks,
        'scope' => 'Actual maintained-library requests and production Oidc class with a deterministic credential-checking provider transport; no live provider or native runtime calls.',
        'publicClientRequirement' => 'The provider must explicitly register this client with token_endpoint_auth_method none and allow authorization code with PKCE S256.']) . "\n";
} catch (Throwable $error) {
    echo json_encode(['suite' => 'final-package-client-auth-methods', 'phpVersion' => PHP_VERSION,
        'passed' => count(array_filter($checks, fn($value) => $value['passed'])), 'checks' => $checks,
        'failure' => $error instanceof AppException ? $error->safeCode : 'TEST_ASSERTION_OR_FIXTURE_FAILURE']) . "\n";
    exit(1);
}
