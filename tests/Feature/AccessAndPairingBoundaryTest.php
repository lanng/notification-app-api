<?php

namespace Tests\Feature;

use App\Enums\PairingRequestStatus;
use App\Models\Installation;
use App\Models\Invitation;
use App\Models\Monitor;
use App\Models\MonitorMembership;
use App\Models\PairingRequest;
use App\Models\User;
use App\Support\AccessAndPairing\OwnerIdentityVerifier;
use App\Support\AccessAndPairing\VerifiedOwnerIdentity;
use Closure;
use Illuminate\Auth\AuthenticationException;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Database\Query\JoinClause;
use Illuminate\Events\Dispatcher;
use Illuminate\Foundation\Testing\LazilyRefreshDatabase;
use Illuminate\Http\Request;
use Illuminate\Log\Logger as IlluminateLogger;
use Illuminate\Routing\Route as RoutingRoute;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use Illuminate\Testing\TestResponse;
use Laravel\Sanctum\PersonalAccessToken;
use LogicException;
use Monolog\Formatter\LineFormatter;
use Monolog\Handler\TestHandler;
use Monolog\Level;
use Monolog\Logger as MonologLogger;
use Monolog\LogRecord;
use PHPUnit\Framework\Attributes\DataProvider;
use RuntimeException;
use Tests\Support\AccessAndPairingFixtures;
use Tests\Support\FakeOwnerIdentityVerifier;
use Tests\TestCase;

class AccessAndPairingBoundaryTest extends TestCase
{
    use LazilyRefreshDatabase;

    public function test_unregistered_method_on_a_v1_route_returns_safe_405_and_allowed_method(): void
    {
        $response = $this->call(
            'GET',
            '/api/v1/pairing-requests',
            server: ['REMOTE_ADDR' => '192.0.2.80'],
        );

        $response->assertMethodNotAllowed()
            ->assertExactJson([
                'code' => 'method_not_allowed',
                'message' => 'Método não permitido.',
            ])
            ->assertHeader('Allow', 'POST');
    }

    public function test_protected_v1_route_returns_safe_401_without_accept_header_or_bearer_token(): void
    {
        $response = $this->requestWithoutAccept('GET', '/api/v1/installation');

        $response->assertUnauthorized()->assertExactJson([
            'code' => 'unauthenticated',
            'message' => 'Autenticação necessária.',
        ]);
    }

    public function test_protected_v1_route_returns_safe_401_without_accept_header_for_invalid_bearer_token(): void
    {
        $response = $this->requestWithoutAccept(
            'GET',
            '/api/v1/installation',
            headers: ['Authorization' => 'Bearer invalid-boundary-token'],
        );

        $response->assertUnauthorized()->assertExactJson([
            'code' => 'unauthenticated',
            'message' => 'Autenticação necessária.',
        ]);
    }

    public function test_guest_redirect_override_is_limited_to_api_v1_paths(): void
    {
        $this->app['url']->resolveMissingNamedRoutesUsing(
            static fn (string $name, array $parameters, bool $absolute): ?string => $name === 'login'
                ? '/login'
                : null,
        );

        $exception = new AuthenticationException;

        $this->assertNull($exception->redirectTo(Request::create('/api/v1/installation')));
        $this->assertSame(
            '/login',
            $exception->redirectTo(Request::create('/api/v2/installation')),
        );
        $this->assertSame(
            '/login',
            $exception->redirectTo(Request::create('/protected')),
        );
    }

    public function test_health_and_non_api_boundaries_keep_their_existing_responses(): void
    {
        $this->get('/api/health')->assertOk()->assertExactJson([
            'status' => 'ok',
        ]);
        $this->get('/up')->assertOk();
        $this->get('/')->assertNotFound();
    }

    public function test_v1_route_inventory_remains_exactly_thirteen_access_routes(): void
    {
        $actual = collect(Route::getRoutes()->getRoutes())
            ->filter(static fn (RoutingRoute $route): bool => str_starts_with($route->uri(), 'api/v1/'))
            ->map(static function (RoutingRoute $route): string {
                $methods = array_values(array_diff($route->methods(), ['HEAD']));
                sort($methods);

                return implode('|', $methods).' '.$route->uri();
            })
            ->sort()
            ->values()
            ->all();

        $expected = [
            'GET api/v1/installation',
            'POST api/v1/monitors/{monitor}/invitations',
            'GET api/v1/monitors/{monitor}/invitations',
            'DELETE api/v1/monitors/{monitor}/invitations/{invitation}',
            'GET api/v1/monitors/{monitor}/pairing-requests',
            'POST api/v1/monitors/{monitor}/pairing-requests/{pairingRequest}/approval',
            'POST api/v1/monitors/{monitor}/pairing-requests/{pairingRequest}/rejection',
            'GET api/v1/monitors/{monitor}/supports',
            'DELETE api/v1/monitors/{monitor}/supports/{membership}',
            'POST api/v1/owner/host-activations',
            'GET api/v1/owner/monitor',
            'POST api/v1/pairing-requests',
            'GET api/v1/pairing-requests/current',
        ];
        sort($expected);

        $this->assertSame($expected, $actual);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function v1MutationRoutes(): array
    {
        return [
            'public redemption' => ['public-redemption'],
            'owner activation' => ['owner-activation'],
            'host approval' => ['host-approval'],
        ];
    }

    #[DataProvider('v1MutationRoutes')]
    public function test_routed_v1_mutations_return_400_for_malformed_json_without_accept_header(string $routeKey): void
    {
        ['uri' => $uri, 'headers' => $headers] = $this->prepareMutationRoute($routeKey);

        $response = $this->requestWithoutAccept('POST', $uri, '{', $headers);

        $response->assertBadRequest()->assertExactJson([
            'code' => 'malformed_json',
            'message' => 'O corpo JSON é inválido.',
        ]);
    }

    /**
     * @return array<string, array{string, ?string}>
     */
    public static function unsupportedMutationMediaTypes(): array
    {
        $cases = [];

        foreach (self::v1MutationRoutes() as $routeName => [$routeKey]) {
            $cases[$routeName.' with unsupported media type'] = [$routeKey, 'text/plain'];
            $cases[$routeName.' without media type'] = [$routeKey, null];
        }

        return $cases;
    }

    #[DataProvider('unsupportedMutationMediaTypes')]
    public function test_routed_v1_mutations_return_415_for_unsupported_or_missing_media_type_without_accept_header(
        string $routeKey,
        ?string $contentType,
    ): void {
        ['uri' => $uri, 'headers' => $headers] = $this->prepareMutationRoute($routeKey);

        $response = $this->requestWithoutAccept('POST', $uri, '{}', $headers, $contentType);

        $response->assertUnsupportedMediaType()->assertExactJson([
            'code' => 'unsupported_media_type',
            'message' => 'O tipo de conteúdo não é suportado.',
        ]);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function nonObjectMutationPayloads(): array
    {
        $cases = [];

        foreach (self::v1MutationRoutes() as $routeName => [$routeKey]) {
            $cases[$routeName.' with array root'] = [$routeKey, '[]'];
            $cases[$routeName.' with null root'] = [$routeKey, 'null'];
        }

        return $cases;
    }

    #[DataProvider('nonObjectMutationPayloads')]
    public function test_routed_v1_mutations_return_422_for_array_or_null_root_without_accept_header(
        string $routeKey,
        string $body,
    ): void {
        ['uri' => $uri, 'headers' => $headers] = $this->prepareMutationRoute($routeKey);

        $response = $this->requestWithoutAccept('POST', $uri, $body, $headers);

        $response->assertUnprocessable()->assertExactJson([
            'code' => 'invalid_payload',
            'message' => 'Os dados enviados são inválidos.',
        ]);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function missingRequiredMutationPayloads(): array
    {
        return [
            'public redemption requires an invitation secret' => ['public-redemption'],
            'owner activation requires confirmation and generation' => ['owner-activation'],
        ];
    }

    #[DataProvider('missingRequiredMutationPayloads')]
    public function test_routed_v1_mutations_return_422_for_missing_required_fields_without_accept_header(
        string $routeKey,
    ): void {
        ['uri' => $uri, 'headers' => $headers] = $this->prepareMutationRoute($routeKey);

        $response = $this->requestWithoutAccept('POST', $uri, '{}', $headers);

        $response->assertUnprocessable()->assertExactJson([
            'code' => 'invalid_payload',
            'message' => 'Os dados enviados são inválidos.',
        ]);
        $this->assertSame(0, Installation::query()->count());
        $this->assertSame(0, PairingRequest::query()->count());
    }

    /**
     * @return array<string, array{string}>
     */
    public static function nonStringRedemptionSecrets(): array
    {
        return [
            'integer secret' => ['{"invitationSecret":7}'],
            'float secret' => ['{"invitationSecret":1.0}'],
            'boolean secret' => ['{"invitationSecret":true}'],
        ];
    }

    #[DataProvider('nonStringRedemptionSecrets')]
    public function test_public_redemption_does_not_coerce_required_json_values_without_accept_header(string $body): void
    {
        $response = $this->requestWithoutAccept('POST', '/api/v1/pairing-requests', $body);

        $response->assertUnprocessable()->assertExactJson([
            'code' => 'invalid_payload',
            'message' => 'Os dados enviados são inválidos.',
            'errors' => [
                'invitationSecret' => ['O valor informado é inválido.'],
            ],
        ]);
        $this->assertSame(0, Installation::query()->count());
        $this->assertSame(0, PairingRequest::query()->count());
    }

    public function test_public_redemption_rejects_unknown_secret_fields_without_echo_or_writes(): void
    {
        $secret = rtrim(strtr(base64_encode(str_repeat("\x04", 32)), '+/', '-_'), '=');
        $rejectedKey = 'synthetic_secret_key_must_not_echo';
        $rejectedValue = 'synthetic-secret-value-must-not-echo';
        $body = json_encode([
            'invitationSecret' => $secret,
            $rejectedKey => $rejectedValue,
        ], JSON_THROW_ON_ERROR);

        $response = $this->requestWithoutAccept('POST', '/api/v1/pairing-requests', $body);

        $response->assertUnprocessable()->assertExactJson([
            'code' => 'invalid_payload',
            'message' => 'Os dados enviados são inválidos.',
        ]);
        $this->assertStringNotContainsString($secret, $response->getContent());
        $this->assertStringNotContainsString($rejectedKey, $response->getContent());
        $this->assertStringNotContainsString($rejectedValue, $response->getContent());
        $this->assertSame(0, Installation::query()->count());
        $this->assertSame(0, PairingRequest::query()->count());
    }

    /**
     * @return array<string, array{string, string}>
     */
    public static function nonNativeActivationScalars(): array
    {
        return [
            'string confirmation' => [
                '{"confirmation":"true","expectedGeneration":"1"}',
                'confirmation',
            ],
            'integer confirmation' => [
                '{"confirmation":1,"expectedGeneration":"1"}',
                'confirmation',
            ],
            'float confirmation' => [
                '{"confirmation":1.0,"expectedGeneration":"1"}',
                'confirmation',
            ],
            'integer generation' => [
                '{"confirmation":true,"expectedGeneration":1}',
                'expectedGeneration',
            ],
            'float generation' => [
                '{"confirmation":true,"expectedGeneration":1.0}',
                'expectedGeneration',
            ],
            'boolean generation' => [
                '{"confirmation":true,"expectedGeneration":true}',
                'expectedGeneration',
            ],
        ];
    }

    #[DataProvider('nonNativeActivationScalars')]
    public function test_owner_activation_rejects_json_scalar_coercion_without_accept_header(
        string $body,
        string $field,
    ): void {
        $host = (new AccessAndPairingFixtures($this))->createHost();

        $response = $this->requestWithoutAccept(
            'POST',
            '/api/v1/owner/host-activations',
            $body,
            ['Authorization' => 'Bearer '.FakeOwnerIdentityVerifier::TEST_BEARER_TOKEN],
        );

        $response->assertUnprocessable()->assertExactJson([
            'code' => 'invalid_payload',
            'message' => 'Os dados enviados são inválidos.',
            'errors' => [
                $field => ['O valor informado é inválido.'],
            ],
        ]);
        $this->assertSame(1, Monitor::query()->whereKey($host['monitor']->id)->value('host_generation'));
        $this->assertSame(1, Installation::query()->count());
    }

    public function test_owner_activation_rejects_unknown_financial_and_reference_fields_without_echo_or_reassignment(): void
    {
        $host = (new AccessAndPairingFixtures($this))->createHost();
        $rejectedKey = 'synthetic_secret_key_must_not_echo';
        $rejectedValue = 'synthetic-secret-value-must-not-echo';
        $body = json_encode([
            'confirmation' => true,
            'expectedGeneration' => '1',
            'requiresReference' => false,
            'balanceCents' => 700,
            'limitCents' => 900,
            'role' => 'Host',
            $rejectedKey => $rejectedValue,
        ], JSON_THROW_ON_ERROR | JSON_PRESERVE_ZERO_FRACTION);

        $response = $this->requestWithoutAccept(
            'POST',
            '/api/v1/owner/host-activations',
            $body,
            ['Authorization' => 'Bearer '.FakeOwnerIdentityVerifier::TEST_BEARER_TOKEN],
        );

        $response->assertUnprocessable()->assertExactJson([
            'code' => 'invalid_payload',
            'message' => 'Os dados enviados são inválidos.',
        ]);
        $this->assertStringNotContainsString($rejectedKey, $response->getContent());
        $this->assertStringNotContainsString($rejectedValue, $response->getContent());
        $this->assertStringNotContainsString('balanceCents', $response->getContent());
        $this->assertStringNotContainsString('limitCents', $response->getContent());
        $this->assertDatabaseHas('monitors', [
            'id' => $host['monitor']->id,
            'user_id' => $host['monitor']->user_id,
            'host_generation' => 1,
            'requires_reference' => true,
        ]);
        $this->assertSame(1, User::query()->whereKey($host['monitor']->user_id)->count());
        $this->assertSame(1, Installation::query()->count());
        $this->assertSame(1, MonitorMembership::query()->count());
    }

    public function test_unknown_invitation_secret_returns_safe_410_without_accept_header(): void
    {
        $secret = rtrim(strtr(base64_encode(str_repeat("\x03", 32)), '+/', '-_'), '=');

        $response = $this->requestWithoutAccept(
            'POST',
            '/api/v1/pairing-requests',
            json_encode(['invitationSecret' => $secret], JSON_THROW_ON_ERROR),
        );

        $response->assertGone()->assertExactJson([
            'code' => 'invitation_unavailable',
            'message' => 'Convite indisponível.',
        ]);
        $this->assertStringNotContainsString($secret, $response->getContent());
        $this->assertSame(0, Installation::query()->count());
        $this->assertSame(0, PairingRequest::query()->count());
    }

    public function test_first_host_activation_rolls_back_all_writes_after_token_insert_failure(): void
    {
        $this->configureOwnerIdentity('first-activation-fault');
        $before = $this->businessSnapshot();

        $failure = $this->requestWithPersistenceFailure(
            'personal_access_tokens',
            'insert',
            fn (): TestResponse => $this->requestWithoutAccept(
                'POST',
                '/api/v1/owner/host-activations',
                '{"confirmation":true,"expectedGeneration":"0"}',
                ['Authorization' => 'Bearer '.FakeOwnerIdentityVerifier::TEST_BEARER_TOKEN],
            ),
        );

        $this->assertObservedBusinessTransactionFailure($failure);
        $this->assertSanitizedInternalError($failure['response']);
        $this->assertSame($before, $this->businessSnapshot());
        $this->assertSame(0, User::query()->count());
        $this->assertSame(0, Monitor::query()->count());
        $this->assertSame(0, Installation::query()->count());
        $this->assertSame(0, MonitorMembership::query()->count());
        $this->assertSame(0, PersonalAccessToken::query()->count());
    }

    public function test_host_swap_rolls_back_revocations_and_pending_retirement_after_new_token_failure(): void
    {
        $this->travelTo('2026-11-21 12:00:00 UTC');
        $fixtures = new AccessAndPairingFixtures($this);
        $host = $fixtures->createHost();
        $support = $fixtures->createSupportInstallation($host['monitor']);
        $availableInvitation = $fixtures->requestJson(
            'POST',
            "/api/v1/monitors/{$host['monitor']->id}/invitations",
            '{}',
            ['Authorization' => 'Bearer '.$host['token']],
        );
        $availableInvitation->assertCreated();
        $candidate = $this->createPendingPairingRequest($fixtures, $host, '198.51.100.192');
        $before = $this->businessSnapshot();

        $failure = $this->requestWithPersistenceFailure(
            'personal_access_tokens',
            'insert',
            fn (): TestResponse => $this->requestWithoutAccept(
                'POST',
                '/api/v1/owner/host-activations',
                '{"confirmation":true,"expectedGeneration":"1"}',
                ['Authorization' => 'Bearer '.FakeOwnerIdentityVerifier::TEST_BEARER_TOKEN],
            ),
        );

        $this->assertObservedBusinessTransactionFailure($failure);
        $this->assertSanitizedInternalError($failure['response']);
        $this->assertSame($before, $this->businessSnapshot());
        $this->assertSame(1, $host['monitor']->fresh()->host_generation);
        $this->assertTrue($host['monitor']->fresh()->requires_reference);
        $this->assertNull($host['membership']->fresh()->revoked_at);
        $this->assertNull($support['membership']->fresh()->revoked_at);
        $this->assertSame(PairingRequestStatus::Pending, PairingRequest::query()
            ->findOrFail($candidate['requestId'])->status);
        $this->assertNotNull(PersonalAccessToken::query()
            ->findOrFail(PersonalAccessToken::findToken($candidate['token'])->id)->expires_at);
        $this->assertDatabaseHas('personal_access_tokens', ['id' => $host['accessToken']->id]);
        $this->assertDatabaseHas('personal_access_tokens', ['id' => $support['accessToken']->id]);
        $this->assertSame(3, Installation::query()->count());
    }

    public function test_invitation_issue_rolls_back_insert_after_database_write_failure(): void
    {
        $fixtures = new AccessAndPairingFixtures($this);
        $host = $fixtures->createHost();
        $existingInvitation = $fixtures->requestJson(
            'POST',
            "/api/v1/monitors/{$host['monitor']->id}/invitations",
            '{}',
            ['Authorization' => 'Bearer '.$host['token']],
        );
        $existingInvitation->assertCreated();
        $before = $this->businessSnapshot($host['accessToken']->id);

        $failure = $this->requestWithPersistenceFailure(
            'invitations',
            'insert',
            fn (): TestResponse => $this->requestWithoutAccept(
                'POST',
                "/api/v1/monitors/{$host['monitor']->id}/invitations",
                '{}',
                ['Authorization' => 'Bearer '.$host['token']],
            ),
        );

        $this->assertObservedBusinessTransactionFailure($failure);
        $this->assertSanitizedInternalError($failure['response']);
        $this->assertStringNotContainsString('invitationSecret', $failure['response']->getContent());
        $this->assertSame($before, $this->businessSnapshot($host['accessToken']->id));
        $this->assertSame(1, Invitation::query()->where('monitor_id', $host['monitor']->id)->count());
        $this->assertDatabaseHas('invitations', ['id' => $existingInvitation->json('data.id')]);
    }

    public function test_invitation_cancel_rolls_back_revocation_after_database_write_failure(): void
    {
        $fixtures = new AccessAndPairingFixtures($this);
        $host = $fixtures->createHost();
        $invitation = $fixtures->requestJson(
            'POST',
            "/api/v1/monitors/{$host['monitor']->id}/invitations",
            '{}',
            ['Authorization' => 'Bearer '.$host['token']],
        );
        $invitation->assertCreated();
        $invitationId = $invitation->json('data.id');
        $secret = $invitation->json('data.invitationSecret');
        $before = $this->businessSnapshot($host['accessToken']->id);

        $failure = $this->requestWithPersistenceFailure(
            'invitations',
            'update',
            fn (): TestResponse => $this->requestWithoutAccept(
                'DELETE',
                "/api/v1/monitors/{$host['monitor']->id}/invitations/{$invitationId}",
                '{}',
                ['Authorization' => 'Bearer '.$host['token']],
            ),
        );

        $this->assertObservedBusinessTransactionFailure($failure);
        $this->assertSanitizedInternalError($failure['response']);
        $this->assertStringNotContainsString($secret, $failure['response']->getContent());
        $this->assertSame($before, $this->businessSnapshot($host['accessToken']->id));
        $this->assertNull(Invitation::query()->findOrFail($invitationId)->revoked_at);
        $this->assertNull(Invitation::query()->findOrFail($invitationId)->consumed_at);
    }

    public function test_public_redemption_rolls_back_consumption_and_credentials_after_token_insert_failure(): void
    {
        $this->travelTo('2026-11-21 12:00:00 UTC');
        $fixtures = new AccessAndPairingFixtures($this);
        $host = $fixtures->createHost();
        $issuedInvitation = $fixtures->requestJson(
            'POST',
            "/api/v1/monitors/{$host['monitor']->id}/invitations",
            '{}',
            ['Authorization' => 'Bearer '.$host['token']],
        );
        $issuedInvitation->assertCreated();
        $secret = $issuedInvitation->json('data.invitationSecret');
        $persistedSecretHash = Invitation::query()
            ->whereKey($issuedInvitation->json('data.id'))
            ->value('secret_hash');
        $sensitiveLabel = 'synthetic-sensitive-request-body-value';
        $body = json_encode([
            'invitationSecret' => $secret,
            'installationLabel' => $sensitiveLabel,
        ], JSON_THROW_ON_ERROR);
        $before = $this->businessSnapshot();
        config(['app.debug' => true]);

        $failure = $this->requestWithPersistenceFailure(
            'personal_access_tokens',
            'insert',
            fn (): TestResponse => $this->requestWithoutAccept(
                'POST',
                '/api/v1/pairing-requests',
                $body,
                ['Authorization' => 'Bearer '.$host['token']],
            ),
        );

        $this->assertObservedBusinessTransactionFailure($failure);
        $this->assertSanitizedInternalError($failure['response']);
        $this->assertStringNotContainsString($secret, $failure['response']->getContent());
        $this->assertStringNotContainsString($host['token'], $failure['response']->getContent());
        $this->assertStringNotContainsString($body, $failure['formattedLogs']);
        $this->assertStringNotContainsString($secret, $failure['formattedLogs']);
        $this->assertStringNotContainsString($host['token'], $failure['formattedLogs']);
        $this->assertStringNotContainsString($sensitiveLabel, $failure['formattedLogs']);
        $this->assertSame(hash('sha256', $secret), $persistedSecretHash);
        $this->assertNotSame($secret, $persistedSecretHash);
        $this->assertSame($before, $this->businessSnapshot());
        $this->assertNull(Invitation::query()->findOrFail($issuedInvitation->json('data.id'))->consumed_at);
        $this->assertSame(0, PairingRequest::query()->count());
        $this->assertSame(1, Installation::query()->count());
    }

    public function test_approval_rolls_back_membership_and_request_after_pending_token_update_failure(): void
    {
        $this->travelTo('2026-11-21 12:00:00 UTC');
        $fixtures = new AccessAndPairingFixtures($this);
        $host = $fixtures->createHost();
        $candidate = $this->createPendingPairingRequest($fixtures, $host, '198.51.100.193');
        $candidateToken = PersonalAccessToken::findToken($candidate['token']);
        $this->assertInstanceOf(PersonalAccessToken::class, $candidateToken);
        $candidateTokenHash = $candidateToken->token;
        $candidateTokenExpiry = $candidateToken->expires_at?->toISOString();
        $before = $this->businessSnapshot($host['accessToken']->id);

        $failure = $this->requestWithPersistenceFailure(
            'personal_access_tokens',
            'update',
            fn (): TestResponse => $this->requestWithoutAccept(
                'POST',
                "/api/v1/monitors/{$host['monitor']->id}/pairing-requests/{$candidate['requestId']}/approval",
                '{}',
                ['Authorization' => 'Bearer '.$host['token']],
            ),
            'expires_at',
        );

        $this->assertObservedBusinessTransactionFailure($failure);
        $this->assertSanitizedInternalError($failure['response']);
        $this->assertSame($before, $this->businessSnapshot($host['accessToken']->id));
        $this->assertSame(PairingRequestStatus::Pending, PairingRequest::query()
            ->findOrFail($candidate['requestId'])->status);
        $this->assertNull(PairingRequest::query()
            ->findOrFail($candidate['requestId'])->decided_at);
        $this->assertSame(0, MonitorMembership::query()
            ->where('installation_id', $candidate['installationId'])
            ->count());
        $candidateToken->refresh();
        $this->assertSame($candidateTokenHash, $candidateToken->token);
        $this->assertSame($candidateTokenExpiry, $candidateToken->expires_at?->toISOString());
    }

    public function test_rejection_rolls_back_decision_and_candidate_credentials_after_token_delete_failure(): void
    {
        $this->travelTo('2026-11-21 12:00:00 UTC');
        $fixtures = new AccessAndPairingFixtures($this);
        $host = $fixtures->createHost();
        $candidate = $this->createPendingPairingRequest($fixtures, $host, '198.51.100.194');
        $candidateToken = PersonalAccessToken::findToken($candidate['token']);
        $this->assertInstanceOf(PersonalAccessToken::class, $candidateToken);
        $candidateTokenId = $candidateToken->id;
        $candidateTokenHash = $candidateToken->token;
        $candidateTokenExpiry = $candidateToken->expires_at?->toISOString();
        $before = $this->businessSnapshot($host['accessToken']->id);

        $failure = $this->requestWithPersistenceFailure(
            'personal_access_tokens',
            'delete',
            fn (): TestResponse => $this->requestWithoutAccept(
                'POST',
                "/api/v1/monitors/{$host['monitor']->id}/pairing-requests/{$candidate['requestId']}/rejection",
                '{}',
                ['Authorization' => 'Bearer '.$host['token']],
            ),
        );

        $this->assertObservedBusinessTransactionFailure($failure);
        $this->assertSanitizedInternalError($failure['response']);
        $this->assertSame($before, $this->businessSnapshot($host['accessToken']->id));
        $this->assertSame(PairingRequestStatus::Pending, PairingRequest::query()
            ->findOrFail($candidate['requestId'])->status);
        $this->assertNull(PairingRequest::query()
            ->findOrFail($candidate['requestId'])->decided_at);
        $this->assertNull(PairingRequest::query()
            ->findOrFail($candidate['requestId'])->decision_actor_membership_id);
        $candidateToken->refresh();
        $this->assertSame($candidateTokenId, $candidateToken->id);
        $this->assertSame($candidateTokenHash, $candidateToken->token);
        $this->assertSame($candidateTokenExpiry, $candidateToken->expires_at?->toISOString());
    }

    public function test_support_revocation_rolls_back_membership_after_token_delete_failure(): void
    {
        $fixtures = new AccessAndPairingFixtures($this);
        $host = $fixtures->createHost();
        $support = $fixtures->createSupportInstallation($host['monitor']);
        $supportTokenHash = $support['accessToken']->token;
        $before = $this->businessSnapshot($host['accessToken']->id);

        $failure = $this->requestWithPersistenceFailure(
            'personal_access_tokens',
            'delete',
            fn (): TestResponse => $this->requestWithoutAccept(
                'DELETE',
                "/api/v1/monitors/{$host['monitor']->id}/supports/{$support['membership']->id}",
                '{}',
                ['Authorization' => 'Bearer '.$host['token']],
            ),
        );

        $this->assertObservedBusinessTransactionFailure($failure);
        $this->assertSanitizedInternalError($failure['response']);
        $this->assertSame($before, $this->businessSnapshot($host['accessToken']->id));
        $this->assertNull($support['membership']->fresh()->revoked_at);
        $this->assertDatabaseHas('personal_access_tokens', [
            'id' => $support['accessToken']->id,
            'token' => $supportTokenHash,
        ]);
        $this->assertDatabaseHas('personal_access_tokens', ['id' => $host['accessToken']->id]);
    }

    public function test_wildcard_support_cannot_list_supports_or_reject_a_pending_pairing_request(): void
    {
        $fixtures = new AccessAndPairingFixtures($this);
        $host = $fixtures->createHost();
        $support = $fixtures->createSupportInstallation($host['monitor']);
        $wildcardToken = $support['installation']->createToken('wildcard-support', ['*'])->plainTextToken;
        $candidate = $this->createPendingPairingRequest($fixtures, $host, '198.51.100.191');
        $candidateToken = PersonalAccessToken::findToken($candidate['token']);
        $this->assertInstanceOf(PersonalAccessToken::class, $candidateToken);
        $candidateTokenHash = $candidateToken->token;
        $candidateTokenExpiry = $candidateToken->expires_at?->toISOString();
        $pairingRequestCount = PairingRequest::query()->count();
        $membershipCount = MonitorMembership::query()->count();

        $listing = $this->requestWithoutAccept(
            'GET',
            "/api/v1/monitors/{$host['monitor']->id}/supports",
            headers: ['Authorization' => 'Bearer '.$wildcardToken],
        );
        $rejection = $this->requestWithoutAccept(
            'POST',
            "/api/v1/monitors/{$host['monitor']->id}/pairing-requests/{$candidate['requestId']}/rejection",
            '{}',
            ['Authorization' => 'Bearer '.$wildcardToken],
        );

        $expectedForbidden = [
            'code' => 'access_forbidden',
            'message' => 'Acesso não permitido.',
        ];
        $listing->assertForbidden()->assertExactJson($expectedForbidden);
        $rejection->assertForbidden()->assertExactJson($expectedForbidden);
        $this->assertSame(PairingRequestStatus::Pending, PairingRequest::query()
            ->findOrFail($candidate['requestId'])->status);
        $this->assertNull(PairingRequest::query()
            ->findOrFail($candidate['requestId'])->decided_at);
        $this->assertNull(PairingRequest::query()
            ->findOrFail($candidate['requestId'])->decision_actor_membership_id);
        $this->assertSame($pairingRequestCount, PairingRequest::query()->count());
        $this->assertSame($membershipCount, MonitorMembership::query()->count());
        $this->assertDatabaseHas('personal_access_tokens', [
            'id' => $candidateToken->id,
            'token' => $candidateTokenHash,
            'expires_at' => $candidateTokenExpiry,
        ]);
    }

    public function test_last_batch_rollback_refuses_populated_access_data_before_dropping_any_table(): void
    {
        $fixtures = new AccessAndPairingFixtures($this);
        $host = $fixtures->createHost();
        $support = $fixtures
            ->createSupportInstallation($host['monitor']);
        $invitation = Invitation::factory()->create([
            'monitor_id' => $host['monitor']->id,
            'issuing_installation_id' => $host['installation']->id,
            'issuing_generation' => 1,
        ]);
        $candidate = Installation::factory()->create();
        PairingRequest::factory()->pending()->create([
            'monitor_id' => $host['monitor']->id,
            'invitation_id' => $invitation->id,
            'installation_id' => $candidate->id,
        ]);
        DB::table('password_reset_tokens')->insert([
            'email' => 'rollback-probe@example.test',
            'token' => hash('sha256', 'synthetic-reset-token'),
            'created_at' => now(),
        ]);
        DB::table('sessions')->insert([
            'id' => 'rollback-probe-session',
            'user_id' => $host['monitor']->user_id,
            'ip_address' => '192.0.2.81',
            'user_agent' => 'synthetic-rollback-probe',
            'payload' => 'synthetic-session-payload',
            'last_activity' => now()->getTimestamp(),
        ]);

        $tables = [
            'users',
            'password_reset_tokens',
            'sessions',
            'monitors',
            'installations',
            'monitor_memberships',
            'invitations',
            'pairing_requests',
            'personal_access_tokens',
        ];
        $before = $this->rollbackProbeSnapshot($tables);
        $connection = DB::connection('pgsql');
        $baselineTransactionLevel = $connection->transactionLevel();
        $connection->beginTransaction();

        try {
            $exitCode = null;
            $rollbackException = null;

            try {
                $exitCode = Artisan::call('migrate:rollback', [
                    '--database' => 'pgsql',
                    '--no-interaction' => true,
                ]);
            } catch (RuntimeException $exception) {
                $rollbackException = $exception;
            }

            $output = Artisan::output();
            $duringProbe = $this->rollbackProbeSnapshot($tables);
        } finally {
            $connection->rollBack($baselineTransactionLevel);
        }

        $after = $this->rollbackProbeSnapshot($tables);

        $this->assertSame($baselineTransactionLevel, $connection->transactionLevel());
        $this->assertSame(
            'Refusing to roll back while owner or access data exists.',
            $rollbackException?->getMessage(),
        );
        $this->assertNotSame(0, $exitCode, $output);
        $this->assertSame($before, $after);
        $this->assertSame($before['tables'], $duringProbe['tables']);
        $this->assertSame($before['rows'], $duringProbe['rows']);
        $this->assertSame($before['schema'], $duringProbe['schema']);
        $this->assertSame($before['migrations'], $duringProbe['migrations']);
        $this->assertInstanceOf(User::class, User::query()->find($host['monitor']->user_id));
        $this->assertInstanceOf(Monitor::class, Monitor::query()->find($host['monitor']->id));
        $this->assertModelExists($host['membership']);
        $this->assertModelExists($support['membership']);
    }

    public function test_last_batch_rollback_is_permitted_when_owner_and_access_tables_are_empty(): void
    {
        $tables = [
            'users',
            'password_reset_tokens',
            'sessions',
            'monitors',
            'installations',
            'monitor_memberships',
            'invitations',
            'pairing_requests',
            'personal_access_tokens',
        ];
        $before = $this->rollbackProbeSnapshot($tables);
        $connection = DB::connection('pgsql');
        $baselineTransactionLevel = $connection->transactionLevel();
        $connection->beginTransaction();

        try {
            $exitCode = Artisan::call('migrate:rollback', [
                '--database' => 'pgsql',
                '--no-interaction' => true,
            ]);
            $duringProbe = $this->rollbackProbeSnapshot($tables);
        } finally {
            $connection->rollBack($baselineTransactionLevel);
        }

        $after = $this->rollbackProbeSnapshot($tables);

        $this->assertSame(0, $exitCode);
        $this->assertSame(array_fill_keys($tables, false), $duringProbe['tables']);
        $this->assertSame(array_fill_keys($tables, [
            'columns' => [],
            'indexes' => [],
            'constraints' => [],
        ]), $duringProbe['schema']);
        $this->assertSame($before, $after);
        $this->assertSame($baselineTransactionLevel, $connection->transactionLevel());
    }

    /**
     * @param  list<string>  $tables
     * @return array{
     *     tables: array<string, bool>,
     *     rows: array<string, list<array<string, mixed>>>,
     *     schema: array<string, array{
     *         columns: list<array<string, mixed>>,
     *         indexes: list<array<string, mixed>>,
     *         constraints: list<array<string, mixed>>
     *     }>,
     *     migrations: list<array<string, mixed>>
     * }
     */
    private function rollbackProbeSnapshot(array $tables): array
    {
        $primaryKeys = [
            'users' => 'id',
            'password_reset_tokens' => 'email',
            'sessions' => 'id',
            'monitors' => 'id',
            'installations' => 'id',
            'monitor_memberships' => 'id',
            'invitations' => 'id',
            'pairing_requests' => 'id',
            'personal_access_tokens' => 'id',
        ];
        $tableExistence = [];
        $rows = [];
        $schema = array_fill_keys($tables, [
            'columns' => [],
            'indexes' => [],
            'constraints' => [],
        ]);

        foreach ($tables as $table) {
            $tableExistence[$table] = Schema::hasTable($table);
            $rows[$table] = Schema::hasTable($table)
                ? array_map(
                    static fn (object $row): array => (array) $row,
                    DB::table($table)->orderBy($primaryKeys[$table])->get()->all(),
                )
                : [];
        }

        $columnDefinitions = DB::table('pg_catalog.pg_attribute as attribute')
            ->join('pg_catalog.pg_class as table_relation', 'table_relation.oid', '=', 'attribute.attrelid')
            ->join('pg_catalog.pg_namespace as table_namespace', 'table_namespace.oid', '=', 'table_relation.relnamespace')
            ->leftJoin('pg_catalog.pg_attrdef as attribute_default', function (JoinClause $join): void {
                $join->on('attribute_default.adrelid', '=', 'attribute.attrelid')
                    ->on('attribute_default.adnum', '=', 'attribute.attnum');
            })
            ->leftJoin('pg_catalog.pg_collation as collation_definition', 'collation_definition.oid', '=', 'attribute.attcollation')
            ->leftJoin('pg_catalog.pg_namespace as collation_namespace', 'collation_namespace.oid', '=', 'collation_definition.collnamespace')
            ->whereRaw('table_namespace.nspname = current_schema()')
            ->whereIn('table_relation.relname', $tables)
            ->whereIn('table_relation.relkind', ['r', 'p'])
            ->where('attribute.attnum', '>', 0)
            ->where('attribute.attisdropped', false)
            ->selectRaw(
                'table_relation.relname AS table_name,
                attribute.attnum AS ordinal_position,
                attribute.attname AS column_name,
                pg_catalog.format_type(attribute.atttypid, attribute.atttypmod) AS data_type,
                attribute.attnotnull AS is_not_null,
                pg_catalog.pg_get_expr(attribute_default.adbin, attribute_default.adrelid) AS default_expression,
                attribute.attidentity AS identity_generation,
                attribute.attgenerated AS generated_kind,
                CASE WHEN collation_definition.oid IS NULL THEN NULL
                    ELSE pg_catalog.quote_ident(collation_namespace.nspname) || \'.\' || pg_catalog.quote_ident(collation_definition.collname)
                END AS collation,
                attribute.attstorage AS storage_strategy,
                attribute.attcompression AS compression_method,
                attribute.attoptions AS storage_options',
            )
            ->orderBy('table_relation.relname')
            ->orderBy('attribute.attnum')
            ->get();

        foreach ($columnDefinitions as $columnDefinition) {
            $schema[$columnDefinition->table_name]['columns'][] = (array) $columnDefinition;
        }

        $indexDefinitions = DB::table('pg_catalog.pg_index as index_metadata')
            ->join('pg_catalog.pg_class as table_relation', 'table_relation.oid', '=', 'index_metadata.indrelid')
            ->join('pg_catalog.pg_namespace as table_namespace', 'table_namespace.oid', '=', 'table_relation.relnamespace')
            ->join('pg_catalog.pg_class as index_relation', 'index_relation.oid', '=', 'index_metadata.indexrelid')
            ->whereRaw('table_namespace.nspname = current_schema()')
            ->whereIn('table_relation.relname', $tables)
            ->selectRaw(
                'table_relation.relname AS table_name,
                index_relation.relname AS index_name,
                pg_catalog.pg_get_indexdef(index_metadata.indexrelid) AS definition,
                index_metadata.indisprimary AS is_primary,
                index_metadata.indisunique AS is_unique,
                index_metadata.indisvalid AS is_valid,
                index_metadata.indisready AS is_ready,
                index_metadata.indislive AS is_live,
                index_metadata.indisclustered AS is_clustered,
                index_metadata.indisreplident AS is_replica_identity',
            )
            ->orderBy('table_relation.relname')
            ->orderBy('index_relation.relname')
            ->get();

        foreach ($indexDefinitions as $indexDefinition) {
            $schema[$indexDefinition->table_name]['indexes'][] = (array) $indexDefinition;
        }

        $constraintDefinitions = DB::table('pg_catalog.pg_constraint as constraint_metadata')
            ->join('pg_catalog.pg_class as table_relation', 'table_relation.oid', '=', 'constraint_metadata.conrelid')
            ->join('pg_catalog.pg_namespace as table_namespace', 'table_namespace.oid', '=', 'table_relation.relnamespace')
            ->whereRaw('table_namespace.nspname = current_schema()')
            ->whereIn('table_relation.relname', $tables)
            ->selectRaw(
                'table_relation.relname AS table_name,
                constraint_metadata.conname AS constraint_name,
                constraint_metadata.contype AS constraint_type,
                pg_catalog.pg_get_constraintdef(constraint_metadata.oid) AS definition,
                constraint_metadata.condeferrable AS is_deferrable,
                constraint_metadata.condeferred AS is_initially_deferred,
                constraint_metadata.convalidated AS is_validated,
                constraint_metadata.connoinherit AS does_not_inherit',
            )
            ->orderBy('table_relation.relname')
            ->orderBy('constraint_metadata.conname')
            ->get();

        foreach ($constraintDefinitions as $constraintDefinition) {
            $schema[$constraintDefinition->table_name]['constraints'][] = (array) $constraintDefinition;
        }

        return [
            'tables' => $tableExistence,
            'rows' => $rows,
            'schema' => $schema,
            'migrations' => array_map(
                static fn (object $row): array => (array) $row,
                DB::table('migrations')->orderBy('migration')->get()->all(),
            ),
        ];
    }

    /**
     * @param  array<string, string>  $headers
     */
    private function requestWithoutAccept(
        string $method,
        string $uri,
        string $body = '',
        array $headers = [],
        ?string $contentType = 'application/json',
    ): TestResponse {
        $server = [
            'REMOTE_ADDR' => '198.51.100.190',
        ];

        if ($contentType !== null) {
            $server['CONTENT_TYPE'] = $contentType;
        }

        foreach ($headers as $name => $value) {
            $server['HTTP_'.strtoupper(str_replace('-', '_', $name))] = $value;
        }

        app('auth')->forgetGuards();

        return $this->call($method, $uri, [], [], [], $server, $body);
    }

    /**
     * @return array{uri: string, headers: array<string, string>}
     */
    private function prepareMutationRoute(string $routeKey): array
    {
        if ($routeKey === 'public-redemption') {
            return [
                'uri' => '/api/v1/pairing-requests',
                'headers' => [],
            ];
        }

        if ($routeKey === 'owner-activation') {
            $this->configureOwnerIdentity('boundary-owner');

            return [
                'uri' => '/api/v1/owner/host-activations',
                'headers' => [
                    'Authorization' => 'Bearer '.FakeOwnerIdentityVerifier::TEST_BEARER_TOKEN,
                ],
            ];
        }

        if ($routeKey === 'host-approval') {
            $host = (new AccessAndPairingFixtures($this))->createHost();

            return [
                'uri' => "/api/v1/monitors/{$host['monitor']->id}/pairing-requests/00000000-0000-4000-8000-000000000010/approval",
                'headers' => ['Authorization' => 'Bearer '.$host['token']],
            ];
        }

        throw new LogicException('The requested v1 route fixture is not supported.');
    }

    /**
     * @param  array{monitor: Monitor, token: string}  $host
     * @return array{requestId: string, installationId: string, token: string}
     */
    private function createPendingPairingRequest(
        AccessAndPairingFixtures $fixtures,
        array $host,
        string $remoteAddress,
    ): array {
        $invitation = $fixtures->requestJson(
            'POST',
            "/api/v1/monitors/{$host['monitor']->id}/invitations",
            '{}',
            ['Authorization' => 'Bearer '.$host['token']],
        );
        $invitation->assertCreated();

        $redemption = $fixtures->requestJson(
            'POST',
            '/api/v1/pairing-requests',
            json_encode(['invitationSecret' => $invitation->json('data.invitationSecret')], JSON_THROW_ON_ERROR),
            remoteAddress: $remoteAddress,
        );
        $redemption->assertCreated();

        return [
            'requestId' => $redemption->json('data.requestId'),
            'installationId' => $redemption->json('data.installationId'),
            'token' => $redemption->json('data.accessToken'),
        ];
    }

    private function configureOwnerIdentity(string $firebaseUid): void
    {
        $firebaseProjectId = 'boundary-test-project';
        config([
            'access_pairing.owner.firebase_project_id' => $firebaseProjectId,
            'access_pairing.owner.firebase_uid' => $firebaseUid,
        ]);
        app()->instance(
            OwnerIdentityVerifier::class,
            new FakeOwnerIdentityVerifier(
                new VerifiedOwnerIdentity(
                    $firebaseProjectId,
                    $firebaseUid,
                    'google.com',
                    now('UTC')->getTimestamp(),
                ),
            ),
        );
    }

    /**
     * @return array{
     *     tables: array<string, bool>,
     *     rows: array<string, list<array<string, mixed>>>
     * }
     */
    private function businessSnapshot(?int $ignoredActorTokenId = null): array
    {
        $tables = [
            'users',
            'password_reset_tokens',
            'sessions',
            'monitors',
            'installations',
            'monitor_memberships',
            'invitations',
            'pairing_requests',
            'personal_access_tokens',
        ];
        $snapshot = $this->rollbackProbeSnapshot($tables);

        if ($ignoredActorTokenId !== null) {
            foreach ($snapshot['rows']['personal_access_tokens'] as &$row) {
                if ((int) $row['id'] === $ignoredActorTokenId) {
                    unset($row['last_used_at'], $row['updated_at']);
                }
            }

            unset($row);
        }

        return [
            'tables' => $snapshot['tables'],
            'rows' => $snapshot['rows'],
        ];
    }

    /**
     * @param  Closure(): TestResponse  $request
     * @return array{
     *     response: TestResponse,
     *     faultTriggered: bool,
     *     baselineTransactionLevel: int,
     *     faultTransactionLevel: ?int,
     *     restoredTransactionLevel: int,
     *     formattedLogs: string
     * }
     */
    private function requestWithPersistenceFailure(
        string $table,
        string $operation,
        Closure $request,
        ?string $requiredSqlFragment = null,
    ): array {
        $connection = DB::connection('pgsql');
        $originalDispatcher = $connection->getEventDispatcher();
        $baselineTransactionLevel = $connection->transactionLevel();

        if (! $originalDispatcher instanceof Dispatcher) {
            throw new LogicException('A database event dispatcher is required by the persistence fault test.');
        }

        $testDispatcher = clone $originalDispatcher;
        $faultTriggered = false;
        $faultTransactionLevel = null;
        $testDispatcher->listen(
            QueryExecuted::class,
            function (QueryExecuted $query) use (
                $connection,
                $table,
                $operation,
                $requiredSqlFragment,
                &$faultTriggered,
                &$faultTransactionLevel,
            ): void {
                if (
                    $faultTriggered
                    || ! $this->isTargetWriteQuery($query->sql, $table, $operation, $requiredSqlFragment)
                ) {
                    return;
                }

                $faultTriggered = true;
                $faultTransactionLevel = $connection->transactionLevel();

                throw new RuntimeException('Synthetic boundary persistence failure.');
            },
        );

        $channel = Log::channel(config('logging.default'));

        if (! $channel instanceof IlluminateLogger) {
            throw new LogicException('The configured log channel is not an Illuminate logger.');
        }

        $monologLogger = $channel->getLogger();

        if (! $monologLogger instanceof MonologLogger) {
            throw new LogicException('The configured log channel is not backed by Monolog.');
        }

        $testHandler = new TestHandler(Level::Debug, bubble: false);
        $monologLogger->pushHandler($testHandler);
        $connection->setEventDispatcher($testDispatcher);

        try {
            $response = $request();
            $records = $testHandler->getRecords();
            $formatter = new LineFormatter;
            $formattedLogs = implode("\n", array_map(
                static fn (LogRecord $record): string => $formatter->format($record),
                $records,
            ));
            $restoredTransactionLevel = $connection->transactionLevel();

            $this->assertNotEmpty($records, 'The HTTP failure should be reported by the configured logger.');
            $this->assertTrue(
                $testHandler->hasRecords(Level::Error),
                'The HTTP failure should be reported at error level.',
            );

            return [
                'response' => $response,
                'faultTriggered' => $faultTriggered,
                'baselineTransactionLevel' => $baselineTransactionLevel,
                'faultTransactionLevel' => $faultTransactionLevel,
                'restoredTransactionLevel' => $restoredTransactionLevel,
                'formattedLogs' => $formattedLogs,
            ];
        } finally {
            $connection->setEventDispatcher($originalDispatcher);
            $monologLogger->popHandler();
        }
    }

    private function isTargetWriteQuery(
        string $sql,
        string $table,
        string $operation,
        ?string $requiredSqlFragment,
    ): bool {
        $tableName = preg_quote($table, '/');
        $pattern = match ($operation) {
            'insert' => '/\Ainsert\s+into\s+"'.$tableName.'"/i',
            'update' => '/\Aupdate\s+"'.$tableName.'"/i',
            'delete' => '/\Adelete\s+from\s+"'.$tableName.'"/i',
            default => throw new LogicException('The requested persistence fault operation is not supported.'),
        };

        return preg_match($pattern, ltrim($sql)) === 1
            && ($requiredSqlFragment === null || str_contains(
                strtolower($sql),
                strtolower($requiredSqlFragment),
            ));
    }

    /**
     * @param  array{
     *     faultTriggered: bool,
     *     baselineTransactionLevel: int,
     *     faultTransactionLevel: ?int,
     *     restoredTransactionLevel: int,
     *     formattedLogs: string
     * }  $failure
     */
    private function assertObservedBusinessTransactionFailure(array $failure): void
    {
        $this->assertTrue($failure['faultTriggered'], 'The failure must follow the selected database write.');
        $this->assertNotNull($failure['faultTransactionLevel']);
        $this->assertGreaterThan(
            $failure['baselineTransactionLevel'],
            $failure['faultTransactionLevel'],
            'The selected database write must occur inside the business transaction.',
        );
        $this->assertSame($failure['baselineTransactionLevel'], $failure['restoredTransactionLevel']);
        $this->assertStringContainsString('Synthetic boundary persistence failure.', $failure['formattedLogs']);
    }

    private function assertSanitizedInternalError(TestResponse $response): void
    {
        $response->assertInternalServerError()->assertExactJson([
            'code' => 'internal_error',
            'message' => 'Erro interno do servidor.',
        ]);
    }
}
