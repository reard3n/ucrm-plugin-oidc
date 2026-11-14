<?php
declare(strict_types=1);
namespace UcrmOidc;

final class Config
{
    public const ENTRY = '/crm/_plugins/ucrm-oidc/public.php';
    public const DEFAULTS = [
        'issuer' => '', 'discoveryUrl' => '', 'clientId' => '', 'canonicalOrigin' => '',
        'clientAuthMethod' => 'client_secret_basic', 'scopes' => 'openid email profile',
        'loginLabel' => 'Sign in with OpenID Connect', 'emailSource' => 'userinfo',
        'emailClaim' => 'email', 'emailVerifiedClaim' => 'email_verified', 'maxAge' => null,
        'endpointOrigins' => [],
    ];

    public static function settings(array $input): array
    {
        self::keys($input, array_merge(array_keys(self::DEFAULTS), ['expectedProviderRevision']));
        $settings = self::DEFAULTS;
        foreach ($settings as $key => $default) {
            if (array_key_exists($key, $input)) { $settings[$key] = $input[$key]; }
        }
        foreach (['issuer', 'clientId', 'canonicalOrigin', 'discoveryUrl', 'scopes', 'loginLabel', 'emailClaim', 'emailVerifiedClaim'] as $key) {
            if (!is_string($settings[$key]) || preg_match('/[\x00-\x1f\x7f]/', $settings[$key])) { throw new AppException('INVALID_SETTINGS'); }
            $settings[$key] = trim($settings[$key]);
        }
        self::url($settings['issuer'], false);
        $origin = self::origin($settings['canonicalOrigin']);
        if ($origin !== $settings['canonicalOrigin']) { throw new AppException('INVALID_CANONICAL_ORIGIN'); }
        if ($settings['discoveryUrl'] === '') { $settings['discoveryUrl'] = rtrim($settings['issuer'], '/') . '/.well-known/openid-configuration'; }
        self::url($settings['discoveryUrl'], false);
        if (!in_array($settings['clientAuthMethod'], ['client_secret_basic', 'client_secret_post', 'none'], true)
            || !in_array($settings['emailSource'], ['userinfo', 'id_token'], true)
            || $settings['clientId'] === '' || strlen($settings['clientId']) > 256
            || $settings['loginLabel'] === '' || mb_strlen($settings['loginLabel']) > 80) { throw new AppException('INVALID_SETTINGS'); }
        if (!preg_match('/\A[\x21\x23-\x5b\x5d-\x7e ]{1,512}\z/D', $settings['scopes'])) { throw new AppException('INVALID_SCOPES'); }
        $scopes = array_values(array_unique(explode(' ', $settings['scopes'])));
        if (in_array('', $scopes, true) || !in_array('openid', $scopes, true) || in_array('offline_access', $scopes, true) || count($scopes) > 16) { throw new AppException('INVALID_SCOPES'); }
        $settings['scopes'] = implode(' ', $scopes);
        foreach (['emailClaim', 'emailVerifiedClaim'] as $key) {
            $claim = $settings[$key];
            if ($claim === '' || strlen($claim) > 256 || (str_starts_with($claim, '/')
                ? preg_match('/~(?![01])/', $claim) || substr_count($claim, '/') > 8
                : !preg_match('/\A[A-Za-z][A-Za-z0-9_.:-]{0,127}\z/D', $claim))) { throw new AppException('INVALID_CLAIM_PATH'); }
        }
        if ($settings['maxAge'] !== null && (!is_int($settings['maxAge']) || $settings['maxAge'] < 0 || $settings['maxAge'] > 86400)) { throw new AppException('INVALID_MAX_AGE'); }
        if (!is_array($settings['endpointOrigins']) || !array_is_list($settings['endpointOrigins']) || count($settings['endpointOrigins']) > 8) { throw new AppException('INVALID_ENDPOINT_ORIGINS'); }
        foreach ($settings['endpointOrigins'] as $allowed) {
            if (!is_string($allowed) || self::origin($allowed) !== $allowed) { throw new AppException('INVALID_ENDPOINT_ORIGINS'); }
        }
        $settings['endpointOrigins'] = array_values(array_unique($settings['endpointOrigins']));
        if (!in_array(self::origin($settings['discoveryUrl']), self::origins($settings), true)) { throw new AppException('ENDPOINT_ORIGIN_DENIED'); }
        return $settings;
    }

    public static function keys(array $value, array $allowed): void
    {
        if (array_diff(array_keys($value), $allowed)) { throw new AppException('UNKNOWN_INPUT'); }
    }
    public static function revision(mixed $value): int
    {
        if (!is_int($value) || $value < 0 || $value > 2147483647) { throw new AppException('INVALID_REVISION'); }
        return $value;
    }
    public static function url(string $url, bool $query = true): array
    {
        if ($url === '' || strlen($url) > 2048 || preg_match('/[\x00-\x20\x7f\\\\]/', $url)
            || preg_match('/%(?:0[0-9a-f]|1[0-9a-f]|7f|5c)/i', $url)) { throw new AppException('INVALID_HTTPS_URL'); }
        $parts = parse_url($url);
        if ($parts === false || ($parts['scheme'] ?? '') !== 'https' || isset($parts['user'], $parts['pass'])
            || isset($parts['user']) || isset($parts['pass']) || isset($parts['fragment'])
            || (!$query && isset($parts['query'])) || !isset($parts['host'])
            || !preg_match('/\A(?:[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?|\[[0-9a-f:]+\])\z/D', $parts['host'])
            || str_contains($parts['host'], '..') || ($parts['port'] ?? 443) < 1 || ($parts['port'] ?? 443) > 65535) {
            throw new AppException('INVALID_HTTPS_URL');
        }
        // cURL normalizes legacy numeric IPv4 forms before applying RESOLVE.
        // Reject spellings that could bypass a pin keyed by the original host.
        if (preg_match('/\A(?:0x[0-9a-f]+|[0-9]+)(?:\.(?:0x[0-9a-f]+|[0-9]+))*\z/Di', $parts['host'])
            && !filter_var($parts['host'], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) { throw new AppException('INVALID_HTTPS_URL'); }
        return $parts;
    }
    public static function origin(string $url): string
    {
        $parts = self::url($url);
        return 'https://' . $parts['host'] . (isset($parts['port']) && $parts['port'] !== 443 ? ':' . $parts['port'] : '');
    }
    public static function origins(array $settings): array
    {
        return array_values(array_unique([self::origin($settings['issuer']), ...$settings['endpointOrigins']]));
    }
    public static function callback(array $settings): string { return $settings['canonicalOrigin'] . self::ENTRY . '?action=callback'; }
    public static function backchannelLogout(array $settings): string { return $settings['canonicalOrigin'] . self::ENTRY . '?action=backchannel-logout'; }

    public static function returnPath(string $value): string
    {
        if ($value === '') { return '/crm/'; }
        if (strlen($value) > 2048 || !preg_match('~\A/(?:crm|nms)(?:/|\z)~', $value)
            || preg_match('/[\x00-\x20\x7f\\\\#]/', $value)
            || preg_match('/%(?:[01][0-9a-f]|7f|2f|5c|25|2e)/i', $value)
            || preg_match('~(?:^|/)\.{1,2}(?:/|\?|$)~', $value)
            || str_contains($value, '//') || preg_match('~/(?:login|logout|_plugins|api)(?:[/?.]|$)~i', $value)) {
            throw new AppException('UNSAFE_RETURN_PATH');
        }
        $parts = parse_url($value);
        if ($parts === false || isset($parts['host']) || isset($parts['scheme']) || isset($parts['fragment'])) { throw new AppException('UNSAFE_RETURN_PATH'); }
        $decodedPath = rawurldecode($parts['path'] ?? '');
        if (preg_match('~/(?:login|logout|_plugins|api)(?:[/?.]|$)~i', $decodedPath)
            || preg_match('/[\x00-\x20\x7f\\\\%]/', $decodedPath)) { throw new AppException('UNSAFE_RETURN_PATH'); }
        return $value;
    }
    public static function claim(array $claims, string $path): mixed
    {
        if (!str_starts_with($path, '/')) { return $claims[$path] ?? null; }
        $value = $claims;
        foreach (explode('/', substr($path, 1)) as $part) {
            $key = str_replace(['~1', '~0'], ['/', '~'], $part);
            if (!is_array($value) || !array_key_exists($key, $value)) { return null; }
            $value = $value[$key];
        }
        return $value;
    }
}
