<?php

namespace Tests\Support;

use GuzzleHttp\Promise\Create;
use GuzzleHttp\Promise\PromiseInterface;
use GuzzleHttp\Psr7\Response;
use Psr\Http\Message\RequestInterface;
use RuntimeException;

use function openssl_csr_new;
use function openssl_csr_sign;
use function openssl_pkey_export;
use function openssl_pkey_new;
use function openssl_sign;
use function openssl_x509_export;

final class FirebaseIdentityFixtures
{
    /**
     * @var array{private_key: string, certificate: string}|null
     */
    private static ?array $keyMaterial = null;

    /**
     * @param  array<string, mixed>  $claimOverrides
     * @param  array<string, mixed>  $headerOverrides
     * @param  list<string>  $omittedClaimNames
     */
    public static function idToken(
        array $claimOverrides = [],
        array $headerOverrides = [],
        array $omittedClaimNames = [],
    ): string {
        $now = now('UTC')->getTimestamp();
        $header = array_replace([
            'alg' => 'RS256',
            'kid' => 'synthetic-google-key',
            'typ' => 'JWT',
        ], $headerOverrides);
        $claims = array_replace([
            'iss' => 'https://securetoken.google.com/firebase-project',
            'aud' => 'firebase-project',
            'sub' => 'firebase-owner',
            'iat' => $now - 30,
            'exp' => $now + 3570,
            'auth_time' => $now - 60,
            'firebase' => [
                'sign_in_provider' => 'google.com',
            ],
        ], $claimOverrides);

        foreach ($omittedClaimNames as $claimName) {
            unset($claims[$claimName]);
        }

        $unsignedToken = self::base64UrlEncode(json_encode($header, JSON_THROW_ON_ERROR))
            .'.'.self::base64UrlEncode(json_encode(
                $claims,
                JSON_THROW_ON_ERROR | JSON_PRESERVE_ZERO_FRACTION,
            ));

        if (! openssl_sign($unsignedToken, $signature, self::keyMaterial()['private_key'], OPENSSL_ALGO_SHA256)) {
            throw new RuntimeException('Unable to sign the synthetic Firebase ID token.');
        }

        return $unsignedToken.'.'.self::base64UrlEncode($signature);
    }

    public static function invalidSignatureIdToken(): string
    {
        [$header, $payload, $encodedSignature] = explode('.', self::idToken());
        $signature = base64_decode(
            strtr($encodedSignature, '-_', '+/').str_repeat('=', (4 - strlen($encodedSignature) % 4) % 4),
            true,
        );

        if (! is_string($signature) || $signature === '') {
            throw new RuntimeException('Unable to alter the synthetic Firebase ID token signature.');
        }

        $signature[0] = chr(ord($signature[0]) ^ 1);

        return $header.'.'.$payload.'.'.self::base64UrlEncode($signature);
    }

    /**
     * @return array<string, string>
     */
    public static function serviceAccount(): array
    {
        return [
            'type' => 'service_account',
            'project_id' => 'firebase-project',
            'private_key_id' => 'synthetic-private-key-marker',
            'private_key' => self::keyMaterial()['private_key'],
            'client_email' => 'firebase-owner@firebase-project.iam.gserviceaccount.com',
            'token_uri' => 'https://oauth2.googleapis.com/token',
        ];
    }

    public static function certificatePem(): string
    {
        return self::keyMaterial()['certificate'];
    }

    public static function certificateResponse(int $maxAge, int $age = 0): Response
    {
        $headers = [
            'Cache-Control' => 'public, max-age='.$maxAge,
            'Content-Type' => 'application/json',
        ];

        if ($age > 0) {
            $headers['Age'] = (string) $age;
        }

        return new Response(200, $headers, json_encode([
            'synthetic-google-key' => self::certificatePem(),
        ], JSON_THROW_ON_ERROR));
    }

    /**
     * @param  list<array<string, mixed>>  $users
     */
    public static function accountResponse(array $users): Response
    {
        return new Response(200, [
            'Content-Type' => 'application/json',
        ], json_encode([
            'users' => $users,
        ], JSON_THROW_ON_ERROR));
    }

    /**
     * @param  array<int, array<string, mixed>>  $requests
     * @param  array<string, Response|\Closure>  $responseOverrides
     */
    public static function transport(
        array &$requests,
        array $responseOverrides = [],
    ): \Closure {
        return static function (
            RequestInterface $request,
            array $options,
        ) use (&$requests, $responseOverrides): PromiseInterface {
            $url = (string) $request->getUri();
            $requests[] = [
                'method' => $request->getMethod(),
                'url' => $url,
                'body' => (string) $request->getBody(),
                'connect_timeout' => $options['connect_timeout'] ?? null,
                'timeout' => $options['timeout'] ?? null,
            ];

            $key = self::requestKey($request);

            if ($key === null) {
                throw new RuntimeException('Unexpected synthetic Firebase HTTP request.');
            }

            $override = $responseOverrides[$key] ?? null;

            if ($override instanceof \Closure) {
                $override = $override($request, $options);
            }

            if ($override instanceof PromiseInterface) {
                return $override;
            }

            if ($override instanceof Response) {
                return Create::promiseFor($override);
            }

            return Create::promiseFor(match ($key) {
                'certificate' => self::certificateResponse(3_600),
                'oauth' => new Response(200, [
                    'Content-Type' => 'application/json',
                ], json_encode([
                    'access_token' => 'synthetic-admin-access-token',
                    'expires_in' => 3600,
                    'token_type' => 'Bearer',
                ], JSON_THROW_ON_ERROR)),
                'account' => new Response(200, [
                    'Content-Type' => 'application/json',
                ], json_encode([
                    'users' => [[
                        'localId' => 'firebase-owner',
                        'createdAt' => '2026-01-01T00:00:00.000Z',
                        'disabled' => false,
                    ]],
                ], JSON_THROW_ON_ERROR)),
            });
        };
    }

    /**
     * @return array{private_key: string, certificate: string}
     */
    private static function keyMaterial(): array
    {
        if (self::$keyMaterial !== null) {
            return self::$keyMaterial;
        }

        $privateKey = openssl_pkey_new([
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
            'private_key_bits' => 2048,
        ]);

        if ($privateKey === false || ! openssl_pkey_export($privateKey, $privateKeyPem)) {
            throw new RuntimeException('Unable to create a synthetic Firebase signing key.');
        }

        $request = openssl_csr_new(['commonName' => 'synthetic.firebase.test'], $privateKey);
        $certificate = $request === false
            ? false
            : openssl_csr_sign($request, null, $privateKey, 3650);

        if ($certificate === false || ! openssl_x509_export($certificate, $certificatePem)) {
            throw new RuntimeException('Unable to create a synthetic Firebase certificate.');
        }

        return self::$keyMaterial = [
            'private_key' => $privateKeyPem,
            'certificate' => $certificatePem,
        ];
    }

    private static function base64UrlEncode(string $value): string
    {
        return rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
    }

    private static function requestKey(RequestInterface $request): ?string
    {
        $uri = $request->getUri();
        $url = (string) $uri;

        if (str_starts_with($url, 'https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com')
            || str_starts_with($url, 'https://www.googleapis.com/oauth2/v1/certs')
            || str_starts_with($url, 'https://www.googleapis.com/identitytoolkit/v3/relyingparty/publicKeys')) {
            return 'certificate';
        }

        if ($uri->getHost() === 'oauth2.googleapis.com' && $uri->getPath() === '/token') {
            return 'oauth';
        }

        if (
            $request->getMethod() === 'POST'
            && $uri->getHost() === 'identitytoolkit.googleapis.com'
            && preg_match('#^/v1/projects/firebase-project/accounts:lookup$#', $uri->getPath()) === 1
        ) {
            return 'account';
        }

        return null;
    }
}
