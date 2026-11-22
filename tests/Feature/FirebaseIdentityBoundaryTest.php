<?php

namespace Tests\Feature;

use App\Models\Installation;
use App\Models\Monitor;
use App\Models\MonitorMembership;
use App\Models\User;
use App\Support\AccessAndPairing\FirebaseVerificationClient;
use GuzzleHttp\Exception\ConnectException;
use GuzzleHttp\Exception\RequestException;
use GuzzleHttp\Promise\Create;
use GuzzleHttp\Promise\PromiseInterface;
use GuzzleHttp\Psr7\Response;
use Illuminate\Foundation\Testing\LazilyRefreshDatabase;
use Illuminate\Log\Logger as IlluminateLogger;
use Illuminate\Support\Facades\Log;
use Illuminate\Testing\TestResponse;
use Kreait\Firebase\Util;
use Laravel\Sanctum\PersonalAccessToken;
use Monolog\Formatter\LineFormatter;
use Monolog\Handler\TestHandler;
use Monolog\Level;
use Monolog\Logger as MonologLogger;
use Monolog\LogRecord;
use PHPUnit\Framework\Attributes\DataProvider;
use Psr\Http\Message\RequestInterface;
use Tests\Support\FirebaseIdentityFixtures;
use Tests\TestCase;
use TypeError;

class FirebaseIdentityBoundaryTest extends TestCase
{
    use LazilyRefreshDatabase;

    public function test_enabled_verifier_rejects_a_missing_bearer_token_without_an_accept_header(): void
    {
        config([
            'access_pairing.firebase.enabled' => true,
            'access_pairing.firebase.credentials_path' => 'unused-in-memory-synthetic-service-account',
            'access_pairing.owner.firebase_project_id' => 'firebase-project',
            'access_pairing.owner.firebase_uid' => 'firebase-owner',
        ]);

        $response = $this->call('GET', '/api/v1/owner/monitor', server: [
            'REMOTE_ADDR' => '192.0.2.91',
        ]);

        $response->assertUnauthorized()->assertExactJson([
            'code' => 'access_unauthenticated',
            'message' => 'Autenticação necessária.',
        ]);
    }

    public function test_certificate_keys_are_reused_until_their_cache_expiry(): void
    {
        $this->travelTo('2026-11-22 12:00:00 UTC');
        $requests = [];
        $this->enableFirebaseVerifier($requests, [
            'certificate' => static fn (): Response => FirebaseIdentityFixtures::certificateResponse(99_999),
        ]);

        $this->getOwnerMonitor(FirebaseIdentityFixtures::idToken())->assertOk();
        $this->assertCount(5, $requests);

        $this->getOwnerMonitor(FirebaseIdentityFixtures::idToken())->assertOk();
        $this->assertCount(7, $requests);

        $this->travel(3601)->seconds();
        $this->getOwnerMonitor(FirebaseIdentityFixtures::idToken())->assertOk();
        $this->assertCount(12, $requests);
    }

    public function test_certificate_cache_respects_upstream_max_age_and_age(): void
    {
        $this->travelTo('2026-11-22 12:00:00 UTC');
        $requests = [];
        $this->enableFirebaseVerifier($requests, [
            'certificate' => static fn (): Response => FirebaseIdentityFixtures::certificateResponse(10, 8),
        ]);

        $this->getOwnerMonitor(FirebaseIdentityFixtures::idToken())->assertOk();
        $this->assertCount(5, $requests);

        $this->travel(1)->seconds();
        $this->getOwnerMonitor(FirebaseIdentityFixtures::idToken())->assertOk();
        $this->assertCount(7, $requests);

        $this->travel(2)->seconds();
        $this->getOwnerMonitor(FirebaseIdentityFixtures::idToken())->assertOk();
        $this->assertCount(12, $requests);
    }

    /**
     * @return array<string, array{array<string, mixed>, array<string, mixed>, list<string>}>
     */
    public static function invalidFirebaseJwtShapes(): array
    {
        return [
            'incorrect issuer' => [['iss' => 'https://attacker.invalid'], [], []],
            'wrong string audience' => [['aud' => 'another-firebase-project'], [], []],
            'audience array' => [['aud' => ['firebase-project']], [], []],
            'non-string subject' => [['sub' => 17], [], []],
            'missing subject' => [[], [], ['sub']],
            'null subject' => [['sub' => null], [], []],
            'empty subject' => [['sub' => ''], [], []],
            'missing expiration' => [[], [], ['exp']],
            'null expiration' => [['exp' => null], [], []],
            'string expiration' => [['exp' => '1795321928'], [], []],
            'floating-point expiration' => [['exp' => 1_795_321_928.0], [], []],
            'expired token' => [['exp' => 1], [], []],
            'missing issued-at time' => [[], [], ['iat']],
            'null issued-at time' => [['iat' => null], [], []],
            'string issued-at time' => [['iat' => '1795348770'], [], []],
            'floating-point issued-at time' => [['iat' => 1_795_348_770.0], [], []],
            'boolean issued-at time' => [['iat' => true], [], []],
            'overflow issued-at time' => [['iat' => PHP_INT_MAX + 1], [], []],
            'missing authentication time' => [[], [], ['auth_time']],
            'null authentication time' => [['auth_time' => null], [], []],
            'string authentication time' => [['auth_time' => '1795348700'], [], []],
            'floating-point authentication time' => [['auth_time' => 1_795_348_700.0], [], []],
            'boolean authentication time' => [['auth_time' => false], [], []],
            'overflow authentication time' => [['auth_time' => PHP_INT_MAX + 1], [], []],
            'future issued-at time' => [['iat' => 4_102_444_800], [], []],
            'future authentication time' => [['auth_time' => 4_102_444_800], [], []],
            'missing sign-in provider' => [['firebase' => []], [], []],
            'non-string sign-in provider' => [[
                'firebase' => ['sign_in_provider' => ['google.com']],
            ], [], []],
            'future not-before time' => [['nbf' => 4_102_444_800], [], []],
            'tenant claim' => [[
                'firebase' => [
                    'sign_in_provider' => 'google.com',
                    'tenant' => 'unconfigured-tenant',
                ],
            ], [], []],
            'unsupported signing algorithm' => [[], ['alg' => 'none'], []],
            'unsupported token type' => [[], ['typ' => 'synthetic'], []],
            'missing signing key id' => [[], ['kid' => null], []],
            'oversized subject' => [['sub' => str_repeat('u', 129)], [], []],
        ];
    }

    /**
     * @param  array<string, mixed>  $claimOverrides
     * @param  array<string, mixed>  $headerOverrides
     */
    #[DataProvider('invalidFirebaseJwtShapes')]
    public function test_invalid_jwt_claim_shapes_return_401_without_fetching_certificates(
        array $claimOverrides,
        array $headerOverrides,
        array $omittedClaimNames = [],
    ): void {
        $this->travelTo('2026-11-22 12:00:00 UTC');
        $requests = [];
        $this->enableFirebaseVerifier($requests);
        $rowsBefore = $this->businessRowCounts();

        $response = $this->getOwnerMonitor(
            FirebaseIdentityFixtures::idToken($claimOverrides, $headerOverrides, $omittedClaimNames),
        );

        $response->assertUnauthorized()->assertExactJson([
            'code' => 'access_unauthenticated',
            'message' => 'Autenticação necessária.',
        ]);
        $this->assertSame([], $requests);
        $this->assertSame($rowsBefore, $this->businessRowCounts());
    }

    public function test_token_expiring_exactly_now_is_rejected_before_fetching_certificates(): void
    {
        $this->travelTo('2026-11-22 12:00:00 UTC');
        $requests = [];
        $this->enableFirebaseVerifier($requests);
        $rowsBefore = $this->businessRowCounts();

        $response = $this->getOwnerMonitor(FirebaseIdentityFixtures::idToken([
            'exp' => now('UTC')->getTimestamp(),
        ]));

        $response->assertUnauthorized()->assertExactJson([
            'code' => 'access_unauthenticated',
            'message' => 'Autenticação necessária.',
        ]);
        $this->assertSame([], $requests);
        $this->assertSame($rowsBefore, $this->businessRowCounts());
    }

    /**
     * @return array<string, array{string}>
     */
    public static function nonOwnerFirebaseProviders(): array
    {
        return [
            'Apple provider' => ['apple.com'],
            'password provider' => ['password'],
            'custom provider' => ['custom'],
            'case-mismatched Google provider' => ['Google.com'],
        ];
    }

    #[DataProvider('nonOwnerFirebaseProviders')]
    public function test_valid_non_google_identity_reaches_owner_authorization_and_returns_403(
        string $provider,
    ): void {
        $this->travelTo('2026-11-22 12:00:00 UTC');
        $requests = [];
        $this->enableFirebaseVerifier($requests);
        $rowsBefore = $this->businessRowCounts();

        $response = $this->getOwnerMonitor(FirebaseIdentityFixtures::idToken([
            'firebase' => ['sign_in_provider' => $provider],
        ]));

        $response->assertForbidden()->assertExactJson([
            'code' => 'owner_not_authorized',
            'message' => 'Esta identidade não está autorizada como proprietária.',
        ]);
        $this->assertCount(3, $requests);
        $this->assertSame(
            [],
            array_filter(
                $requests,
                static fn (array $request): bool => str_contains($request['url'], 'accounts:lookup'),
            ),
        );
        $this->assertSame($rowsBefore, $this->businessRowCounts());
    }

    public function test_firebase_uid_with_128_unicode_characters_reaches_owner_authorization(): void
    {
        $this->travelTo('2026-11-22 12:00:00 UTC');
        $requests = [];
        $this->enableFirebaseVerifier($requests);

        $response = $this->getOwnerMonitor(FirebaseIdentityFixtures::idToken([
            'sub' => str_repeat('ü', 128),
            'firebase' => ['sign_in_provider' => 'apple.com'],
        ]));

        $response->assertForbidden()->assertExactJson([
            'code' => 'owner_not_authorized',
            'message' => 'Esta identidade não está autorizada como proprietária.',
        ]);
        $this->assertCount(3, $requests);
    }

    public function test_valid_google_identity_with_another_uid_reaches_owner_authorization_and_returns_403(): void
    {
        $this->travelTo('2026-11-22 12:00:00 UTC');
        $requests = [];
        $this->enableFirebaseVerifier($requests, [
            'account' => FirebaseIdentityFixtures::accountResponse([[
                'localId' => 'another-firebase-user',
                'createdAt' => '2026-01-01T00:00:00.000Z',
                'disabled' => false,
            ]]),
        ]);

        $response = $this->getOwnerMonitor(FirebaseIdentityFixtures::idToken([
            'sub' => 'another-firebase-user',
        ]));

        $response->assertForbidden()->assertExactJson([
            'code' => 'owner_not_authorized',
            'message' => 'Esta identidade não está autorizada como proprietária.',
        ]);
        $this->assertCount(1, array_filter(
            $requests,
            static fn (array $request): bool => str_contains($request['url'], 'accounts:lookup'),
        ));
    }

    public function test_invalid_signature_returns_401_without_exposing_the_token(): void
    {
        $this->travelTo('2026-11-22 12:00:00 UTC');
        $requests = [];
        $this->enableFirebaseVerifier($requests);
        $token = FirebaseIdentityFixtures::invalidSignatureIdToken();

        $response = $this->getOwnerMonitor($token);

        $response->assertUnauthorized()->assertExactJson([
            'code' => 'access_unauthenticated',
            'message' => 'Autenticação necessária.',
        ]);
        $this->assertStringNotContainsString($token, $response->getContent());
        $this->assertCount(3, $requests);
    }

    public function test_unknown_signing_key_id_returns_401_without_authentication_requests_or_token_logging(): void
    {
        $this->travelTo('2026-11-22 12:00:00 UTC');
        $requests = [];
        $this->enableFirebaseVerifier($requests, [
            'certificate' => static fn (): Response => FirebaseIdentityFixtures::certificateResponse(3_600),
        ]);
        $token = FirebaseIdentityFixtures::idToken([], [
            'kid' => 'unknown-synthetic-key',
        ]);
        $rowsBefore = $this->businessRowCounts();

        $captured = $this->withCapturedConfiguredLogs(
            fn (): TestResponse => $this->getOwnerMonitor($token),
        );

        $captured['response']->assertUnauthorized()->assertExactJson([
            'code' => 'access_unauthenticated',
            'message' => 'Autenticação necessária.',
        ]);
        $this->assertCount(3, $requests);
        $this->assertCount(3, array_filter(
            $requests,
            static fn (array $request): bool => str_contains($request['url'], 'www.googleapis.com/'),
        ));
        $this->assertSame(
            [],
            array_filter(
                $requests,
                static fn (array $request): bool => str_contains($request['url'], 'oauth2.googleapis.com/token')
                    || str_contains($request['url'], 'accounts:lookup'),
            ),
        );
        $this->assertSame($rowsBefore, $this->businessRowCounts());
        $this->assertStringNotContainsString($token, $captured['formattedLogs']);
        $this->assertStringNotContainsString(substr($token, 0, 15), $captured['formattedLogs']);
    }

    public function test_token_with_an_extra_segment_returns_401_without_network_access(): void
    {
        $requests = [];
        $this->enableFirebaseVerifier($requests);

        $response = $this->getOwnerMonitor('header.payload.signature.extra');

        $response->assertUnauthorized()->assertExactJson([
            'code' => 'access_unauthenticated',
            'message' => 'Autenticação necessária.',
        ]);
        $this->assertSame([], $requests);
    }

    public function test_oversized_bearer_token_returns_401_without_network_access(): void
    {
        $requests = [];
        $this->enableFirebaseVerifier($requests);

        $response = $this->getOwnerMonitor(str_repeat('a', 16_385));

        $response->assertUnauthorized()->assertExactJson([
            'code' => 'access_unauthenticated',
            'message' => 'Autenticação necessária.',
        ]);
        $this->assertSame([], $requests);
    }

    public function test_expiration_more_than_one_hour_after_issue_time_returns_401(): void
    {
        $this->travelTo('2026-11-22 12:00:00 UTC');
        $requests = [];
        $this->enableFirebaseVerifier($requests);
        $now = now('UTC')->getTimestamp();

        $response = $this->getOwnerMonitor(FirebaseIdentityFixtures::idToken([
            'iat' => $now,
            'exp' => $now + 3601,
        ]));

        $response->assertUnauthorized()->assertExactJson([
            'code' => 'access_unauthenticated',
            'message' => 'Autenticação necessária.',
        ]);
        $this->assertSame([], $requests);
    }

    public function test_authentication_time_after_issue_time_returns_401(): void
    {
        $this->travelTo('2026-11-22 12:00:00 UTC');
        $requests = [];
        $this->enableFirebaseVerifier($requests);
        $now = now('UTC')->getTimestamp();

        $response = $this->getOwnerMonitor(FirebaseIdentityFixtures::idToken([
            'iat' => $now - 60,
            'auth_time' => $now - 30,
        ]));

        $response->assertUnauthorized()->assertExactJson([
            'code' => 'access_unauthenticated',
            'message' => 'Autenticação necessária.',
        ]);
        $this->assertSame([], $requests);
    }

    public function test_disabled_firebase_user_returns_401(): void
    {
        $this->travelTo('2026-11-22 12:00:00 UTC');
        $requests = [];
        $this->enableFirebaseVerifier($requests, [
            'account' => FirebaseIdentityFixtures::accountResponse([[
                'localId' => 'firebase-owner',
                'createdAt' => '2026-01-01T00:00:00.000Z',
                'disabled' => true,
            ]]),
        ]);

        $response = $this->getOwnerMonitor(FirebaseIdentityFixtures::idToken());

        $response->assertUnauthorized()->assertExactJson([
            'code' => 'access_unauthenticated',
            'message' => 'Autenticação necessária.',
        ]);
        $this->assertCount(1, array_filter(
            $requests,
            static fn (array $request): bool => str_contains($request['url'], 'accounts:lookup'),
        ));
    }

    public function test_deleted_firebase_user_returns_401(): void
    {
        $this->travelTo('2026-11-22 12:00:00 UTC');
        $requests = [];
        $this->enableFirebaseVerifier($requests, [
            'account' => FirebaseIdentityFixtures::accountResponse([]),
        ]);

        $response = $this->getOwnerMonitor(FirebaseIdentityFixtures::idToken());

        $response->assertUnauthorized()->assertExactJson([
            'code' => 'access_unauthenticated',
            'message' => 'Autenticação necessária.',
        ]);
        $this->assertCount(1, array_filter(
            $requests,
            static fn (array $request): bool => str_contains($request['url'], 'accounts:lookup'),
        ));
    }

    /**
     * @return array<string, array{int, int}>
     */
    public static function firebaseValidSinceBoundaries(): array
    {
        return [
            'authentication after validSince' => [1_795_348_680, 200],
            'authentication exactly at validSince' => [1_795_348_740, 200],
            'authentication before validSince' => [1_795_348_741, 401],
        ];
    }

    #[DataProvider('firebaseValidSinceBoundaries')]
    public function test_firebase_token_is_revoked_only_when_authentication_precedes_valid_since(
        int $validSince,
        int $expectedStatus,
    ): void {
        $this->travelTo('2026-11-22 12:00:00 UTC');
        $requests = [];
        $this->enableFirebaseVerifier($requests, [
            'account' => FirebaseIdentityFixtures::accountResponse([[
                'localId' => 'firebase-owner',
                'createdAt' => '2026-01-01T00:00:00.000Z',
                'disabled' => false,
                'validSince' => (string) $validSince,
            ]]),
        ]);
        $rowsBefore = $this->businessRowCounts();

        $response = $this->getOwnerMonitor(FirebaseIdentityFixtures::idToken([
            'auth_time' => 1_795_348_740,
        ]));

        if ($expectedStatus === 401) {
            $response->assertUnauthorized()->assertExactJson([
                'code' => 'access_unauthenticated',
                'message' => 'Autenticação necessária.',
            ]);
        } else {
            $response->assertOk()->assertExactJson([
                'data' => [
                    'monitor' => null,
                    'generation' => '0',
                    'host' => null,
                    'requiresReference' => true,
                ],
            ]);
        }

        $this->assertSame($rowsBefore, $this->businessRowCounts());
        $this->assertCount(1, array_filter(
            $requests,
            static fn (array $request): bool => str_contains($request['url'], 'accounts:lookup'),
        ));
    }

    public function test_stale_signed_owner_can_discover_but_cannot_activate_a_host(): void
    {
        $this->travelTo('2026-11-22 12:00:00 UTC');
        $requests = [];
        $this->enableFirebaseVerifier($requests);
        $token = FirebaseIdentityFixtures::idToken([
            'iat' => 1_795_348_770,
            'exp' => 1_795_352_370,
            'auth_time' => 1_795_348_200,
        ]);
        $rowsBefore = $this->businessRowCounts();

        $discovery = $this->getOwnerMonitor($token);

        $discovery->assertOk()->assertExactJson([
            'data' => [
                'monitor' => null,
                'generation' => '0',
                'host' => null,
                'requiresReference' => true,
            ],
        ]);
        $this->assertSame($rowsBefore, $this->businessRowCounts());

        $activation = $this->postJson('/api/v1/owner/host-activations', [
            'confirmation' => true,
            'expectedGeneration' => '0',
        ], [
            'Authorization' => 'Bearer '.$token,
        ]);

        $activation->assertForbidden()->assertExactJson([
            'code' => 'recent_authentication_required',
            'message' => 'É necessária uma autenticação recente para ativar o dispositivo.',
        ]);
        $this->assertSame($rowsBefore, $this->businessRowCounts());
        $this->assertCount(2, array_filter(
            $requests,
            static fn (array $request): bool => str_contains($request['url'], 'accounts:lookup'),
        ));
    }

    public function test_tenant_scoped_firebase_account_returns_401_without_a_tenant_token_claim(): void
    {
        $this->travelTo('2026-11-22 12:00:00 UTC');
        $requests = [];
        $this->enableFirebaseVerifier($requests, [
            'account' => FirebaseIdentityFixtures::accountResponse([[
                'localId' => 'firebase-owner',
                'createdAt' => '2026-01-01T00:00:00.000Z',
                'disabled' => false,
                'tenantId' => 'unconfigured-tenant',
            ]]),
        ]);

        $response = $this->getOwnerMonitor(FirebaseIdentityFixtures::idToken());

        $response->assertUnauthorized()->assertExactJson([
            'code' => 'access_unauthenticated',
            'message' => 'Autenticação necessária.',
        ]);
    }

    public function test_certificate_service_failure_returns_safe_503(): void
    {
        $this->travelTo('2026-11-22 12:00:00 UTC');
        $requests = [];
        $this->enableFirebaseVerifier($requests, [
            'certificate' => new Response(503, [], 'synthetic-certificate-upstream-detail'),
        ]);
        $token = FirebaseIdentityFixtures::idToken();

        $failure = $this->withCapturedConfiguredLogs(
            fn (): TestResponse => $this->getOwnerMonitor($token),
        );

        $failure['response']->assertServiceUnavailable()->assertExactJson([
            'code' => 'identity_verification_unavailable',
            'message' => 'Verificação de identidade indisponível.',
        ]);
        $this->assertCount(1, $requests);
        $this->assertStringNotContainsString(
            'synthetic-certificate-upstream-detail',
            $failure['response']->getContent(),
        );
        $this->assertStringNotContainsString('synthetic-certificate-upstream-detail', $failure['formattedLogs']);
        $this->assertFirebaseSecretsAbsentFromLogs($failure['formattedLogs'], $token);
    }

    public function test_unexpected_certificate_transport_error_uses_normal_safe_internal_error_reporting(): void
    {
        $this->travelTo('2026-11-22 12:00:00 UTC');
        $requests = [];
        $failureMarker = 'synthetic_firebase_transport_programming_error';
        $this->enableFirebaseVerifier($requests, [
            'certificate' => static function (
                RequestInterface $request,
                array $options,
            ) use ($failureMarker): never {
                throw new TypeError($failureMarker);
            },
        ]);
        $token = FirebaseIdentityFixtures::idToken();
        $rowsBefore = $this->businessRowCounts();

        $failure = $this->withCapturedConfiguredLogs(
            fn (): TestResponse => $this->getOwnerMonitor($token),
        );

        $failure['response']->assertInternalServerError()->assertExactJson([
            'code' => 'internal_error',
            'message' => 'Erro interno do servidor.',
        ]);
        $this->assertSame($rowsBefore, $this->businessRowCounts());
        $this->assertCount(1, $requests);
        $this->assertNotEmpty($failure['records']);
        $this->assertTrue($failure['handler']->hasRecords(Level::Error));
        $this->assertStringContainsString($failureMarker, $failure['formattedLogs']);
        $this->assertFirebaseSecretsAbsentFromLogs($failure['formattedLogs'], $token);
    }

    public function test_unexpected_account_transport_error_uses_normal_safe_internal_error_reporting(): void
    {
        $this->travelTo('2026-11-22 12:00:00 UTC');
        $requests = [];
        $failureMarker = 'synthetic_firebase_account_programming_error';
        $this->enableFirebaseVerifier($requests, [
            'account' => static function (
                RequestInterface $request,
                array $options,
            ) use ($failureMarker): never {
                throw new TypeError($failureMarker);
            },
        ]);
        $token = FirebaseIdentityFixtures::idToken();
        $rowsBefore = $this->businessRowCounts();

        $failure = $this->withCapturedConfiguredLogs(
            fn (): TestResponse => $this->getOwnerMonitor($token),
        );

        $failure['response']->assertInternalServerError()->assertExactJson([
            'code' => 'internal_error',
            'message' => 'Erro interno do servidor.',
        ]);
        $this->assertSame($rowsBefore, $this->businessRowCounts());
        $this->assertCount(5, $requests);
        $this->assertNotEmpty($failure['records']);
        $this->assertTrue($failure['handler']->hasRecords(Level::Error));
        $this->assertStringContainsString($failureMarker, $failure['formattedLogs']);
        $this->assertFirebaseSecretsAbsentFromLogs($failure['formattedLogs'], $token);
    }

    public function test_invalid_service_account_signing_key_returns_safe_503_without_secret_logging(): void
    {
        $this->travelTo('2026-11-22 12:00:00 UTC');
        $requests = [];
        $privateKeyMarker = 'synthetic-invalid-private-key-marker';
        $privateKeyIdMarker = 'synthetic-invalid-private-key-id-marker';
        $serviceAccount = FirebaseIdentityFixtures::serviceAccount();
        $serviceAccount['private_key'] = $privateKeyMarker;
        $serviceAccount['private_key_id'] = $privateKeyIdMarker;
        $this->enableFirebaseVerifier($requests, [], $serviceAccount);
        $token = FirebaseIdentityFixtures::idToken();
        $rowsBefore = $this->businessRowCounts();

        $failure = $this->withCapturedConfiguredLogs(
            fn (): TestResponse => $this->getOwnerMonitor($token),
        );

        $failure['response']->assertServiceUnavailable()->assertExactJson([
            'code' => 'identity_verification_unavailable',
            'message' => 'Verificação de identidade indisponível.',
        ]);
        $this->assertSame($rowsBefore, $this->businessRowCounts());
        $this->assertCount(3, $requests);
        $this->assertSame(
            [],
            array_filter(
                $requests,
                static fn (array $request): bool => str_contains($request['url'], 'oauth2.googleapis.com/token')
                    || str_contains($request['url'], 'accounts:lookup'),
            ),
        );
        $this->assertNotEmpty($failure['records']);
        $this->assertTrue($failure['handler']->hasRecords(Level::Error));
        $this->assertFirebaseSecretsAbsentFromLogs($failure['formattedLogs'], $token);
        $this->assertStringNotContainsString($privateKeyMarker, $failure['formattedLogs']);
        $this->assertStringNotContainsString($privateKeyIdMarker, $failure['formattedLogs']);
        $this->assertStringNotContainsString('Firebase\\JWT', $failure['formattedLogs']);
    }

    public function test_empty_certificate_key_sets_return_safe_503_without_authentication_requests(): void
    {
        $this->travelTo('2026-11-22 12:00:00 UTC');
        $requests = [];
        $this->enableFirebaseVerifier($requests, [
            'certificate' => new Response(
                200,
                ['Content-Type' => 'application/json'],
                '{}',
            ),
        ]);
        $rowsBefore = $this->businessRowCounts();

        $response = $this->getOwnerMonitor(FirebaseIdentityFixtures::idToken());

        $response->assertServiceUnavailable()->assertExactJson([
            'code' => 'identity_verification_unavailable',
            'message' => 'Verificação de identidade indisponível.',
        ]);
        $this->assertCount(3, $requests);
        $this->assertCount(3, array_filter(
            $requests,
            static fn (array $request): bool => str_contains($request['url'], 'www.googleapis.com/'),
        ));
        $this->assertSame(
            [],
            array_filter(
                $requests,
                static fn (array $request): bool => str_contains($request['url'], 'oauth2.googleapis.com/token')
                    || str_contains($request['url'], 'accounts:lookup'),
            ),
        );
        $this->assertSame($rowsBefore, $this->businessRowCounts());
    }

    public function test_malformed_certificate_keys_return_safe_503(): void
    {
        $this->travelTo('2026-11-22 12:00:00 UTC');
        $requests = [];
        $this->enableFirebaseVerifier($requests, [
            'certificate' => static fn (): Response => new Response(
                200,
                ['Cache-Control' => 'public, max-age=3600'],
                '{"synthetic-google-key":"not-a-public-key"}',
            ),
        ]);

        $response = $this->getOwnerMonitor(FirebaseIdentityFixtures::idToken());

        $response->assertServiceUnavailable()->assertExactJson([
            'code' => 'identity_verification_unavailable',
            'message' => 'Verificação de identidade indisponível.',
        ]);
        $this->assertCount(3, $requests);
    }

    public function test_account_service_failure_returns_safe_503(): void
    {
        $this->travelTo('2026-11-22 12:00:00 UTC');
        $requests = [];
        $this->enableFirebaseVerifier($requests, [
            'account' => new Response(
                503,
                ['Content-Type' => 'application/json'],
                '{"error":{"code":503,"message":"synthetic-account-upstream-detail"}}',
            ),
        ]);
        $token = FirebaseIdentityFixtures::idToken();

        $failure = $this->withCapturedConfiguredLogs(
            fn (): TestResponse => $this->getOwnerMonitor($token),
        );

        $failure['response']->assertServiceUnavailable()->assertExactJson([
            'code' => 'identity_verification_unavailable',
            'message' => 'Verificação de identidade indisponível.',
        ]);
        $this->assertCount(5, $requests);
        $this->assertStringNotContainsString(
            'synthetic-account-upstream-detail',
            $failure['response']->getContent(),
        );
        $this->assertStringNotContainsString('synthetic-account-upstream-detail', $failure['formattedLogs']);
        $this->assertFirebaseSecretsAbsentFromLogs($failure['formattedLogs'], $token);
    }

    /**
     * @return array<string, array{string, string, int}>
     */
    public static function externalTransportFailures(): array
    {
        return [
            'certificate connection failure' => ['certificate', 'connection', 1],
            'certificate timeout' => ['certificate', 'timeout', 1],
            'account connection failure' => ['account', 'connection', 5],
            'account timeout' => ['account', 'timeout', 5],
            'OAuth connection failure' => ['oauth', 'connection', 4],
            'OAuth timeout' => ['oauth', 'timeout', 4],
            'OAuth service failure' => ['oauth', 'service_unavailable', 4],
        ];
    }

    #[DataProvider('externalTransportFailures')]
    public function test_expected_external_transport_failures_return_safe_503(
        string $stage,
        string $failureType,
        int $expectedRequestCount,
    ): void {
        $this->travelTo('2026-11-22 12:00:00 UTC');
        $requests = [];
        $token = FirebaseIdentityFixtures::idToken();
        $rowsBefore = $this->businessRowCounts();

        $failure = match ($failureType) {
            'connection' => static function (
                RequestInterface $request,
                array $options,
            ): PromiseInterface {
                return Create::rejectionFor(new ConnectException(
                    'Synthetic connection failure: synthetic-upstream-response-private-marker',
                    $request,
                ));
            },
            'timeout' => static function (
                RequestInterface $request,
                array $options,
            ): PromiseInterface {
                return Create::rejectionFor(new RequestException(
                    'cURL error 28: synthetic upstream response private marker',
                    $request,
                ));
            },
            'service_unavailable' => new Response(
                503,
                ['Content-Type' => 'application/json'],
                '{"error":"synthetic-upstream-response-private-marker"}',
            ),
        };
        $this->enableFirebaseVerifier($requests, [
            $stage => $failure,
        ]);

        $captured = $this->withCapturedConfiguredLogs(
            fn (): TestResponse => $this->getOwnerMonitor($token),
        );

        $captured['response']->assertServiceUnavailable()->assertExactJson([
            'code' => 'identity_verification_unavailable',
            'message' => 'Verificação de identidade indisponível.',
        ]);
        $this->assertSame($rowsBefore, $this->businessRowCounts());
        $this->assertCount($expectedRequestCount, $requests);
        $this->assertSame(
            1,
            count(array_filter(
                $requests,
                static fn (array $request): bool => match ($stage) {
                    'certificate' => str_contains($request['url'], 'www.googleapis.com/'),
                    'oauth' => str_contains($request['url'], 'oauth2.googleapis.com/token'),
                    'account' => str_contains($request['url'], 'accounts:lookup'),
                },
            )),
        );
        $this->assertStringNotContainsString(
            'synthetic-upstream-response-private-marker',
            $captured['response']->getContent(),
        );
        $this->assertFirebaseSecretsAbsentFromLogs($captured['formattedLogs'], $token);
    }

    public function test_unreadable_service_account_file_returns_safe_503(): void
    {
        $this->travelTo('2026-11-22 12:00:00 UTC');
        $requests = [];
        config([
            'access_pairing.firebase.enabled' => true,
            'access_pairing.firebase.credentials_path' => '/synthetic/nonexistent-service-account.json',
            'access_pairing.owner.firebase_project_id' => 'firebase-project',
            'access_pairing.owner.firebase_uid' => 'firebase-owner',
        ]);
        $this->app->instance(
            FirebaseVerificationClient::class,
            new FirebaseVerificationClient(
                'firebase-project',
                '/synthetic/nonexistent-service-account.json',
                FirebaseIdentityFixtures::transport($requests),
            ),
        );

        $response = $this->getOwnerMonitor(FirebaseIdentityFixtures::idToken());

        $response->assertServiceUnavailable()->assertExactJson([
            'code' => 'identity_verification_unavailable',
            'message' => 'Verificação de identidade indisponível.',
        ]);
        $this->assertCount(3, $requests);
    }

    public function test_enabled_verifier_without_credentials_returns_503_without_network_access(): void
    {
        config([
            'access_pairing.firebase.enabled' => true,
            'access_pairing.firebase.credentials_path' => null,
            'access_pairing.owner.firebase_project_id' => 'firebase-project',
            'access_pairing.owner.firebase_uid' => 'firebase-owner',
        ]);

        $response = $this->getOwnerMonitor('synthetic-bearer-token');

        $response->assertServiceUnavailable()->assertExactJson([
            'code' => 'identity_verification_unavailable',
            'message' => 'Verificação de identidade indisponível.',
        ]);
    }

    public function test_invalid_firebase_project_configuration_returns_safe_503(): void
    {
        config([
            'access_pairing.firebase.enabled' => true,
            'access_pairing.firebase.credentials_path' => 'unused-in-memory-synthetic-service-account',
            'access_pairing.owner.firebase_project_id' => ['not-a-project-id'],
            'access_pairing.owner.firebase_uid' => 'firebase-owner',
        ]);

        $response = $this->getOwnerMonitor('synthetic-bearer-token');

        $response->assertServiceUnavailable()->assertExactJson([
            'code' => 'identity_verification_unavailable',
            'message' => 'Verificação de identidade indisponível.',
        ]);
    }

    public function test_non_positive_upstream_timeout_returns_503_without_network_access(): void
    {
        $this->travelTo('2026-11-22 12:00:00 UTC');
        $requests = [];
        $this->enableFirebaseVerifier($requests);
        config(['access_pairing.firebase.timeout' => 0]);

        $response = $this->getOwnerMonitor(FirebaseIdentityFixtures::idToken());

        $response->assertServiceUnavailable()->assertExactJson([
            'code' => 'identity_verification_unavailable',
            'message' => 'Verificação de identidade indisponível.',
        ]);
        $this->assertSame([], $requests);
    }

    public function test_firebase_auth_emulator_configuration_returns_503_without_network_access(): void
    {
        $name = 'FIREBASE_AUTH_EMULATOR_HOST';
        $previousServerValue = $_SERVER[$name] ?? null;
        $previousEnvironmentValue = $_ENV[$name] ?? null;
        $previousProcessValue = getenv($name);
        $hadServerValue = array_key_exists($name, $_SERVER);
        $hadEnvironmentValue = array_key_exists($name, $_ENV);
        $requests = [];

        Util::putenv($name, '127.0.0.1:9099');

        try {
            $this->enableFirebaseVerifier($requests);
            $response = $this->getOwnerMonitor(FirebaseIdentityFixtures::idToken());

            $response->assertServiceUnavailable()->assertExactJson([
                'code' => 'identity_verification_unavailable',
                'message' => 'Verificação de identidade indisponível.',
            ]);
            $this->assertSame([], $requests);
        } finally {
            if ($hadServerValue) {
                $_SERVER[$name] = $previousServerValue;
            } else {
                unset($_SERVER[$name]);
            }

            if ($hadEnvironmentValue) {
                $_ENV[$name] = $previousEnvironmentValue;
            } else {
                unset($_ENV[$name]);
            }

            if ($previousProcessValue === false) {
                putenv($name);
            } else {
                putenv($name.'='.$previousProcessValue);
            }
        }
    }

    /**
     * @param  array<int, array<string, mixed>>  $requests
     * @param  array<string, Response|\Closure>  $responseOverrides
     * @param  array<string, mixed>|string|null  $serviceAccount
     */
    private function enableFirebaseVerifier(
        array &$requests,
        array $responseOverrides = [],
        array|string|null $serviceAccount = null,
    ): void {
        config([
            'access_pairing.firebase.enabled' => true,
            'access_pairing.firebase.credentials_path' => 'unused-in-memory-synthetic-service-account',
            'access_pairing.owner.firebase_project_id' => 'firebase-project',
            'access_pairing.owner.firebase_uid' => 'firebase-owner',
        ]);

        $this->app->instance(
            FirebaseVerificationClient::class,
            new FirebaseVerificationClient(
                'firebase-project',
                $serviceAccount ?? FirebaseIdentityFixtures::serviceAccount(),
                FirebaseIdentityFixtures::transport($requests, $responseOverrides),
            ),
        );
    }

    /**
     * @return array{
     *     users: int,
     *     monitors: int,
     *     installations: int,
     *     memberships: int,
     *     personal_access_tokens: int
     * }
     */
    private function businessRowCounts(): array
    {
        return [
            'users' => User::query()->count(),
            'monitors' => Monitor::query()->count(),
            'installations' => Installation::query()->count(),
            'memberships' => MonitorMembership::query()->count(),
            'personal_access_tokens' => PersonalAccessToken::query()->count(),
        ];
    }

    /**
     * @return array{
     *     response: TestResponse,
     *     formattedLogs: string,
     *     records: array<int, LogRecord>,
     *     handler: TestHandler
     * }
     */
    private function withCapturedConfiguredLogs(\Closure $request): array
    {
        $channel = Log::channel(config('logging.default'));

        if (! $channel instanceof IlluminateLogger) {
            throw new \LogicException('The configured log channel is not an Illuminate logger.');
        }

        $logger = $channel->getLogger();

        if (! $logger instanceof MonologLogger) {
            throw new \LogicException('The configured log channel is not backed by Monolog.');
        }

        $handler = new TestHandler(Level::Debug, bubble: false);
        $logger->pushHandler($handler);

        try {
            $response = $request();
            $records = $handler->getRecords();
            $formatter = new LineFormatter;

            return [
                'response' => $response,
                'formattedLogs' => implode("\n", array_map(
                    static fn (LogRecord $record): string => $formatter->format($record),
                    $records,
                )),
                'records' => $records,
                'handler' => $handler,
            ];
        } finally {
            $logger->popHandler();
        }
    }

    private function assertFirebaseSecretsAbsentFromLogs(string $logs, string $token): void
    {
        $this->assertStringNotContainsString($token, $logs);
        $this->assertStringNotContainsString(substr($token, 0, 15), $logs);
        $this->assertStringNotContainsString('Bearer synthetic-admin-access-token', $logs);
        $this->assertStringNotContainsString('synthetic-admin-access-token', $logs);
        $this->assertStringNotContainsString('synthetic-private-key-marker', $logs);
        $this->assertStringNotContainsString(FirebaseIdentityFixtures::serviceAccount()['private_key'], $logs);
        $this->assertStringNotContainsString('synthetic-upstream-response-private-marker', $logs);
    }

    private function getOwnerMonitor(string $token): TestResponse
    {
        return $this->get('/api/v1/owner/monitor', [
            'Authorization' => 'Bearer '.$token,
            'Accept' => 'application/json',
        ]);
    }
}
