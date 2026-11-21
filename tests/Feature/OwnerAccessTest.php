<?php

namespace Tests\Feature;

use App\Enums\AccessRole;
use App\Enums\PairingRequestStatus;
use App\Models\Installation;
use App\Models\Invitation;
use App\Models\Monitor;
use App\Models\MonitorMembership;
use App\Models\PairingRequest;
use App\Models\User;
use App\Support\AccessAndPairing\OwnerIdentityVerifier;
use App\Support\AccessAndPairing\VerifiedOwnerIdentity;
use Illuminate\Foundation\Testing\LazilyRefreshDatabase;
use Illuminate\Support\Str;
use Illuminate\Testing\TestResponse;
use Laravel\Sanctum\PersonalAccessToken;
use PHPUnit\Framework\Attributes\DataProvider;
use Tests\Support\FakeOwnerIdentityVerifier;
use Tests\TestCase;

class OwnerAccessTest extends TestCase
{
    use LazilyRefreshDatabase;

    public function test_default_verifier_returns_503_for_owner_discovery_without_writing_records(): void
    {
        $usersBefore = User::query()->count();

        $response = $this->get('/api/v1/owner/monitor', [
            'Authorization' => 'Bearer invented-owner-credential',
        ]);

        $response->assertServiceUnavailable()->assertExactJson([
            'code' => 'identity_verification_unavailable',
            'message' => 'Verificação de identidade indisponível.',
        ]);
        $this->assertSame($usersBefore, User::query()->count());
    }

    public function test_default_verifier_returns_503_for_host_activation_without_writing_records(): void
    {
        $usersBefore = User::query()->count();

        $response = $this->postActivationBody('{"confirmation":true,"expectedGeneration":"0"}');

        $response->assertServiceUnavailable()->assertExactJson([
            'code' => 'identity_verification_unavailable',
            'message' => 'Verificação de identidade indisponível.',
        ]);
        $this->assertSame($usersBefore, User::query()->count());
        $this->assertSame(0, Monitor::query()->count());
        $this->assertSame(0, Installation::query()->count());
    }

    public function test_configured_owner_discovers_an_empty_monitor_without_creating_an_account(): void
    {
        $this->useFakeOwnerIdentity(
            new VerifiedOwnerIdentity('firebase-project', 'firebase-owner', 'google.com', now()->timestamp),
        );
        config([
            'access_pairing.owner.firebase_project_id' => 'firebase-project',
            'access_pairing.owner.firebase_uid' => 'firebase-owner',
        ]);
        $usersBefore = User::query()->count();
        $monitorsBefore = Monitor::query()->count();
        $installationsBefore = Installation::query()->count();

        $response = $this->get('/api/v1/owner/monitor', [
            'Authorization' => 'Bearer '.FakeOwnerIdentityVerifier::TEST_BEARER_TOKEN,
        ]);

        $response->assertOk()->assertExactJson([
            'data' => [
                'monitor' => null,
                'generation' => '0',
                'host' => null,
                'requiresReference' => true,
            ],
        ]);
        $this->assertSame($usersBefore, User::query()->count());
        $this->assertSame($monitorsBefore, Monitor::query()->count());
        $this->assertSame($installationsBefore, Installation::query()->count());
    }

    /**
     * @return array<string, array{array<string, string>}>
     */
    public static function invalidFakeOwnerAuthorizationHeaders(): array
    {
        return [
            'missing' => [[]],
            'FCM credential' => [['Authorization' => 'Bearer synthetic-fcm-token']],
            'unrecognized credential' => [['Authorization' => 'Bearer another-token']],
        ];
    }

    /**
     * @param  array<string, string>  $headers
     */
    #[DataProvider('invalidFakeOwnerAuthorizationHeaders')]
    public function test_fake_verifier_rejects_missing_and_unrecognized_credentials_without_writes(array $headers): void
    {
        $this->useFakeOwnerIdentity(
            new VerifiedOwnerIdentity('firebase-project', 'firebase-owner', 'google.com', now()->timestamp),
        );
        $usersBefore = User::query()->count();

        $response = $this->get('/api/v1/owner/monitor', $headers);

        $response->assertUnauthorized()->assertExactJson([
            'code' => 'access_unauthenticated',
            'message' => 'Autenticação necessária.',
        ]);
        $this->assertSame($usersBefore, User::query()->count());
    }

    /**
     * @return array<string, array{string, string, string}>
     */
    public static function identitiesNotConfiguredAsOwner(): array
    {
        return [
            'wrong Firebase project' => ['other-project', 'firebase-owner', 'google.com'],
            'wrong Firebase UID' => ['firebase-project', 'other-owner', 'google.com'],
            'non-Google provider' => ['firebase-project', 'firebase-owner', 'apple.com'],
        ];
    }

    #[DataProvider('identitiesNotConfiguredAsOwner')]
    public function test_discovery_forbids_identity_not_configured_as_owner_without_provisioning(
        string $firebaseProjectId,
        string $firebaseUid,
        string $provider,
    ): void {
        $this->useFakeOwnerIdentity(
            new VerifiedOwnerIdentity($firebaseProjectId, $firebaseUid, $provider, now()->timestamp),
        );
        config([
            'access_pairing.owner.firebase_project_id' => 'firebase-project',
            'access_pairing.owner.firebase_uid' => 'firebase-owner',
        ]);
        $usersBefore = User::query()->count();

        $response = $this->get('/api/v1/owner/monitor', [
            'Authorization' => 'Bearer '.FakeOwnerIdentityVerifier::TEST_BEARER_TOKEN,
        ]);

        $response->assertForbidden()->assertExactJson([
            'code' => 'owner_not_authorized',
            'message' => 'Esta identidade não está autorizada como proprietária.',
        ]);
        $this->assertSame($usersBefore, User::query()->count());
    }

    public function test_discovery_forbids_owner_identity_when_configuration_is_missing(): void
    {
        config([
            'access_pairing.owner.firebase_project_id' => null,
            'access_pairing.owner.firebase_uid' => 'firebase-owner',
        ]);
        $this->useFakeOwnerIdentity(
            new VerifiedOwnerIdentity('firebase-project', 'firebase-owner', 'google.com', now()->timestamp),
        );
        $usersBefore = User::query()->count();

        $response = $this->get('/api/v1/owner/monitor', [
            'Authorization' => 'Bearer '.FakeOwnerIdentityVerifier::TEST_BEARER_TOKEN,
        ]);

        $response->assertForbidden()->assertExactJson([
            'code' => 'owner_not_authorized',
            'message' => 'Esta identidade não está autorizada como proprietária.',
        ]);
        $this->assertSame($usersBefore, User::query()->count());
    }

    public function test_activation_forbids_identity_when_configured_owner_pair_does_not_match(): void
    {
        $this->useConfiguredFakeOwnerIdentity(now()->timestamp);
        config(['access_pairing.owner.firebase_uid' => 'different-owner']);
        $usersBefore = User::query()->count();

        $response = $this->postActivationBody('{"confirmation":true,"expectedGeneration":"0"}');

        $response->assertForbidden()->assertExactJson([
            'code' => 'owner_not_authorized',
            'message' => 'Esta identidade não está autorizada como proprietária.',
        ]);
        $this->assertSame($usersBefore, User::query()->count());
        $this->assertSame(0, Monitor::query()->count());
        $this->assertSame(0, Installation::query()->count());
    }

    public function test_confirmed_recent_owner_activation_creates_a_host_and_returns_one_time_token(): void
    {
        $this->travelTo('2026-11-20 12:00:00 UTC');
        $this->useConfiguredFakeOwnerIdentity(now()->timestamp);

        $response = $this->postActivationBody('{"confirmation":true,"expectedGeneration":"0"}');

        $response->assertCreated();
        $data = $response->json('data');
        $this->assertSame(['data'], array_keys($response->json()));
        $this->assertSame([
            'monitorId',
            'installationId',
            'membershipId',
            'role',
            'generation',
            'requiresReference',
            'accessToken',
            'createdAt',
        ], array_keys($data));
        $this->assertTrue(Str::isUuid($data['monitorId']));
        $this->assertTrue(Str::isUuid($data['installationId']));
        $this->assertTrue(Str::isUuid($data['membershipId']));
        $this->assertSame('Host', $data['role']);
        $this->assertSame('1', $data['generation']);
        $this->assertTrue($data['requiresReference']);
        $this->assertSame(1795176000000, $data['createdAt']);
        $this->assertSame(1, User::query()->count());
        $this->assertSame(1, Monitor::query()->count());
        $this->assertSame(1, Installation::query()->count());
        $this->assertSame(1, MonitorMembership::query()->count());
        $this->assertSame(1, PersonalAccessToken::query()->count());

        $monitor = Monitor::query()->findOrFail($data['monitorId']);
        $installation = Installation::query()->findOrFail($data['installationId']);
        $membership = MonitorMembership::query()->findOrFail($data['membershipId']);
        $storedToken = PersonalAccessToken::findToken($data['accessToken']);

        $this->assertSame(1, $monitor->host_generation);
        $this->assertTrue($monitor->requires_reference);
        $this->assertNull($installation->label);
        $this->assertSame(AccessRole::Host, $membership->role);
        $this->assertSame(1, $membership->generation);
        $this->assertNotNull($storedToken);
        $this->assertSame(Installation::class, $storedToken->tokenable_type);
        $this->assertSame($installation->id, $storedToken->tokenable_id);
        $plainSecret = substr($data['accessToken'], strpos($data['accessToken'], '|') + 1);
        $this->assertSame(hash('sha256', $plainSecret), $storedToken->token);
        $this->assertNotSame($plainSecret, $storedToken->token);
        $this->assertSame(['host:monitor'], $storedToken->abilities);
        $this->assertNull($storedToken->expires_at);
    }

    /**
     * @return array<string, array{string, array<string, list<string>>}>
     */
    public static function invalidHostActivationPayloads(): array
    {
        return [
            'missing confirmation' => ['{"expectedGeneration":"0"}', []],
            'missing expected generation' => ['{"confirmation":true}', []],
            'unknown field' => ['{"confirmation":true,"expectedGeneration":"0","label":"host"}', []],
            'false confirmation' => [
                '{"confirmation":false,"expectedGeneration":"0"}',
                ['confirmation' => ['O valor informado é inválido.']],
            ],
            'integer confirmation' => [
                '{"confirmation":1,"expectedGeneration":"0"}',
                ['confirmation' => ['O valor informado é inválido.']],
            ],
            'integer generation' => [
                '{"confirmation":true,"expectedGeneration":0}',
                ['expectedGeneration' => ['O valor informado é inválido.']],
            ],
            'float generation' => [
                '{"confirmation":true,"expectedGeneration":1.0}',
                ['expectedGeneration' => ['O valor informado é inválido.']],
            ],
            'negative generation' => [
                '{"confirmation":true,"expectedGeneration":"-1"}',
                ['expectedGeneration' => ['O valor informado é inválido.']],
            ],
            'noncanonical generation' => [
                '{"confirmation":true,"expectedGeneration":"00"}',
                ['expectedGeneration' => ['O valor informado é inválido.']],
            ],
            'generation exceeds signed integer range' => [
                '{"confirmation":true,"expectedGeneration":"9223372036854775808"}',
                ['expectedGeneration' => ['O valor informado é inválido.']],
            ],
        ];
    }

    /**
     * @param  array<string, list<string>>  $errors
     */
    #[DataProvider('invalidHostActivationPayloads')]
    public function test_activation_rejects_noncontract_json_payloads_with_422_without_writes(
        string $body,
        array $errors,
    ): void {
        $this->useConfiguredFakeOwnerIdentity(now()->timestamp);
        $usersBefore = User::query()->count();
        $monitorsBefore = Monitor::query()->count();
        $installationsBefore = Installation::query()->count();

        $response = $this->postActivationBody($body);

        $expected = [
            'code' => 'invalid_payload',
            'message' => 'Os dados enviados são inválidos.',
        ];

        if ($errors !== []) {
            $expected['errors'] = $errors;
        }

        $response->assertUnprocessable()->assertExactJson($expected);
        $this->assertSame($usersBefore, User::query()->count());
        $this->assertSame($monitorsBefore, Monitor::query()->count());
        $this->assertSame($installationsBefore, Installation::query()->count());
    }

    public function test_activation_rejects_malformed_json_with_400_before_identity_verification(): void
    {
        $response = $this->postActivationBody('{', 'application/json');

        $response->assertBadRequest()->assertExactJson([
            'code' => 'malformed_json',
            'message' => 'O corpo JSON é inválido.',
        ]);
    }

    public function test_activation_rejects_unsupported_media_type_with_415_before_identity_verification(): void
    {
        $response = $this->postActivationBody('{}', 'text/plain');

        $response->assertUnsupportedMediaType()->assertExactJson([
            'code' => 'unsupported_media_type',
            'message' => 'O tipo de conteúdo não é suportado.',
        ]);
    }

    /**
     * @return array<string, array{int, int}>
     */
    public static function ownerAuthenticationAges(): array
    {
        return [
            'exactly five minutes old' => [-300, 201],
            'more than five minutes old' => [-301, 403],
            'one second in the future' => [1, 403],
        ];
    }

    #[DataProvider('ownerAuthenticationAges')]
    public function test_activation_requires_recent_authentication_with_a_300_second_inclusive_window(
        int $offset,
        int $expectedStatus,
    ): void {
        $this->travelTo('2026-11-20 12:00:00 UTC');
        $this->useConfiguredFakeOwnerIdentity(now()->timestamp + $offset);
        $usersBefore = User::query()->count();

        $response = $this->postActivationBody('{"confirmation":true,"expectedGeneration":"0"}');

        if ($expectedStatus === 201) {
            $response->assertCreated();
            $this->assertSame($usersBefore + 1, User::query()->count());

            return;
        }

        $response->assertForbidden()->assertExactJson([
            'code' => 'recent_authentication_required',
            'message' => 'É necessária uma autenticação recente para ativar o dispositivo.',
        ]);
        $this->assertSame($usersBefore, User::query()->count());
        $this->assertSame(0, Monitor::query()->count());
    }

    public function test_first_activation_generation_conflict_rolls_back_the_new_owner(): void
    {
        $this->useConfiguredFakeOwnerIdentity(now()->timestamp);
        $usersBefore = User::query()->count();
        $monitorsBefore = Monitor::query()->count();
        $installationsBefore = Installation::query()->count();

        $response = $this->postActivationBody('{"confirmation":true,"expectedGeneration":"1"}');

        $response->assertConflict()->assertExactJson([
            'code' => 'generation_conflict',
            'message' => 'A geração informada não corresponde ao estado atual.',
        ]);
        $this->assertSame($usersBefore, User::query()->count());
        $this->assertSame($monitorsBefore, Monitor::query()->count());
        $this->assertSame($installationsBefore, Installation::query()->count());
    }

    public function test_stale_generation_conflict_leaves_the_existing_owner_monitor_unchanged(): void
    {
        $user = User::factory()->create([
            'firebase_project_id' => 'firebase-project',
            'firebase_uid' => 'firebase-owner',
        ]);
        $monitor = Monitor::factory()->for($user)->create([
            'host_generation' => 1,
            'requires_reference' => false,
        ]);
        $this->useConfiguredFakeOwnerIdentity(now()->timestamp);

        $response = $this->postActivationBody('{"confirmation":true,"expectedGeneration":"0"}');

        $response->assertConflict()->assertExactJson([
            'code' => 'generation_conflict',
            'message' => 'A geração informada não corresponde ao estado atual.',
        ]);
        $this->assertSame(1, User::query()->count());
        $this->assertSame(1, Monitor::query()->count());
        $this->assertSame(0, Installation::query()->count());
        $this->assertSame(1, $monitor->fresh()->host_generation);
        $this->assertFalse($monitor->fresh()->requires_reference);
    }

    public function test_generation_overflow_returns_409_without_mutating_the_monitor(): void
    {
        $user = User::factory()->create([
            'firebase_project_id' => 'firebase-project',
            'firebase_uid' => 'firebase-owner',
        ]);
        $monitor = Monitor::factory()->for($user)->create([
            'host_generation' => PHP_INT_MAX,
            'requires_reference' => false,
        ]);
        $this->useConfiguredFakeOwnerIdentity(now()->timestamp);

        $response = $this->postActivationBody(
            '{"confirmation":true,"expectedGeneration":"'.PHP_INT_MAX.'"}',
        );

        $response->assertConflict()->assertExactJson([
            'code' => 'generation_conflict',
            'message' => 'A geração atual não pode ser incrementada.',
        ]);
        $this->assertSame(PHP_INT_MAX, $monitor->fresh()->host_generation);
        $this->assertFalse($monitor->fresh()->requires_reference);
        $this->assertSame(0, Installation::query()->count());
    }

    public function test_owner_discovery_does_not_require_recent_authentication_and_returns_only_current_host_fields(): void
    {
        $user = User::factory()->create([
            'firebase_project_id' => 'firebase-project',
            'firebase_uid' => 'firebase-owner',
        ]);
        $monitor = Monitor::factory()->for($user)->create([
            'host_generation' => 2,
            'requires_reference' => false,
        ]);
        $staleInstallation = Installation::factory()->create(['label' => 'retired host']);
        MonitorMembership::factory()->host()->create([
            'monitor_id' => $monitor->id,
            'installation_id' => $staleInstallation->id,
            'generation' => 1,
            'revoked_at' => now(),
        ]);
        $currentInstallation = Installation::factory()->create(['label' => 'current host']);
        MonitorMembership::factory()->host()->create([
            'monitor_id' => $monitor->id,
            'installation_id' => $currentInstallation->id,
            'generation' => 2,
        ]);
        $this->useConfiguredFakeOwnerIdentity(now()->timestamp - 3600);

        $response = $this->get('/api/v1/owner/monitor', [
            'Authorization' => 'Bearer '.FakeOwnerIdentityVerifier::TEST_BEARER_TOKEN,
        ]);

        $response->assertOk()->assertExactJson([
            'data' => [
                'monitor' => ['id' => $monitor->id],
                'generation' => '2',
                'host' => [
                    'installationId' => $currentInstallation->id,
                    'label' => 'current host',
                ],
                'requiresReference' => true,
            ],
        ]);
        $this->assertStringNotContainsString('retired host', $response->getContent());
    }

    public function test_owner_configuration_change_does_not_discover_or_reassign_an_existing_owner_monitor(): void
    {
        $originalOwner = User::factory()->create([
            'firebase_project_id' => 'original-project',
            'firebase_uid' => 'original-owner',
        ]);
        $monitor = Monitor::factory()->for($originalOwner)->create();
        config([
            'access_pairing.owner.firebase_project_id' => 'new-project',
            'access_pairing.owner.firebase_uid' => 'new-owner',
        ]);
        $this->useFakeOwnerIdentity(
            new VerifiedOwnerIdentity('new-project', 'new-owner', 'google.com', now()->timestamp),
        );

        $response = $this->get('/api/v1/owner/monitor', [
            'Authorization' => 'Bearer '.FakeOwnerIdentityVerifier::TEST_BEARER_TOKEN,
        ]);

        $response->assertOk()->assertExactJson([
            'data' => [
                'monitor' => null,
                'generation' => '0',
                'host' => null,
                'requiresReference' => true,
            ],
        ]);
        $this->assertDatabaseHas('users', [
            'id' => $originalOwner->id,
            'firebase_project_id' => 'original-project',
            'firebase_uid' => 'original-owner',
        ]);
        $this->assertSame($originalOwner->id, $monitor->fresh()->user_id);
    }

    public function test_host_swap_revokes_only_the_old_host_and_cancels_pending_work_from_its_generation(): void
    {
        $this->travelTo('2026-11-20 12:00:00 UTC');
        $user = User::factory()->create([
            'firebase_project_id' => 'firebase-project',
            'firebase_uid' => 'firebase-owner',
        ]);
        $monitor = Monitor::factory()->for($user)->create([
            'host_generation' => 1,
            'requires_reference' => false,
        ]);

        $oldHostInstallation = Installation::factory()->create(['label' => 'old host']);
        $oldHost = MonitorMembership::factory()->host()->create([
            'monitor_id' => $monitor->id,
            'installation_id' => $oldHostInstallation->id,
            'generation' => 1,
        ]);
        $oldHostToken = $oldHostInstallation->createToken('old-host-token', ['host:monitor']);

        $supportInstallation = Installation::factory()->create(['label' => 'approved support']);
        $supportMembership = MonitorMembership::factory()->create([
            'monitor_id' => $monitor->id,
            'installation_id' => $supportInstallation->id,
            'role' => AccessRole::Support,
            'generation' => null,
        ]);
        $supportToken = $supportInstallation->createToken('support-token', ['support:monitor']);

        $pendingInstallation = Installation::factory()->create(['label' => 'pending support']);
        $pendingInvitation = Invitation::factory()->create([
            'monitor_id' => $monitor->id,
            'issuing_installation_id' => $oldHostInstallation->id,
            'issuing_generation' => 1,
            'expires_at' => now()->addHour(),
        ]);
        $pendingRequest = PairingRequest::factory()->pending()->create([
            'monitor_id' => $monitor->id,
            'invitation_id' => $pendingInvitation->id,
            'installation_id' => $pendingInstallation->id,
            'request_expires_at' => now()->addMinutes(10),
        ]);
        $pendingToken = $pendingInstallation->createToken('pending-temporary-token', ['pairing:pending']);

        $approvedInvitation = Invitation::factory()->create([
            'monitor_id' => $monitor->id,
            'issuing_installation_id' => $oldHostInstallation->id,
            'issuing_generation' => 1,
            'expires_at' => now()->addHour(),
            'consumed_at' => now(),
        ]);
        $approvedRequest = PairingRequest::factory()->create([
            'monitor_id' => $monitor->id,
            'invitation_id' => $approvedInvitation->id,
            'installation_id' => $supportInstallation->id,
            'status' => PairingRequestStatus::Approved,
            'request_expires_at' => now()->addMinutes(10),
            'decided_at' => now(),
            'decision_actor_membership_id' => $supportMembership->id,
        ]);
        $this->useConfiguredFakeOwnerIdentity(now()->timestamp);

        $response = $this->postActivationBody('{"confirmation":true,"expectedGeneration":"1"}');

        $response->assertOk();
        $data = $response->json('data');
        $this->assertSame([
            'monitorId',
            'installationId',
            'membershipId',
            'role',
            'generation',
            'requiresReference',
            'accessToken',
            'createdAt',
        ], array_keys($data));
        $this->assertSame($monitor->id, $data['monitorId']);
        $this->assertNotSame($oldHostInstallation->id, $data['installationId']);
        $this->assertSame('Host', $data['role']);
        $this->assertSame('2', $data['generation']);
        $this->assertTrue($data['requiresReference']);
        $this->assertSame(1795176000000, $data['createdAt']);

        $this->assertSame(1, Monitor::query()->count());
        $this->assertSame(4, Installation::query()->count());
        $this->assertSame(3, MonitorMembership::query()->count());
        $this->assertNotNull($oldHost->fresh()->revoked_at);
        $this->assertDatabaseMissing('personal_access_tokens', ['id' => $oldHostToken->accessToken->id]);
        $this->assertDatabaseMissing('personal_access_tokens', ['id' => $pendingToken->accessToken->id]);
        $this->assertSame(PairingRequestStatus::Cancelled, $pendingRequest->fresh()->status);
        $this->assertNotNull($pendingRequest->fresh()->decided_at);
        $this->assertNotNull($pendingInvitation->fresh()->revoked_at);

        $this->assertSame(AccessRole::Support, $supportMembership->fresh()->role);
        $this->assertNull($supportMembership->fresh()->revoked_at);
        $this->assertNotNull(PersonalAccessToken::findToken($supportToken->plainTextToken));
        $this->assertSame(PairingRequestStatus::Approved, $approvedRequest->fresh()->status);
        $this->assertNull($approvedInvitation->fresh()->revoked_at);

        $newHostMembership = MonitorMembership::query()->findOrFail($data['membershipId']);
        $newToken = PersonalAccessToken::findToken($data['accessToken']);
        $this->assertSame(AccessRole::Host, $newHostMembership->role);
        $this->assertSame(2, $newHostMembership->generation);
        $this->assertNotNull($newToken);
        $this->assertSame($data['installationId'], $newToken->tokenable_id);
        $this->assertNull($newToken->expires_at);
        $this->assertSame(2, $monitor->fresh()->host_generation);
        $this->assertTrue($monitor->fresh()->requires_reference);
    }

    private function useFakeOwnerIdentity(VerifiedOwnerIdentity $identity): void
    {
        $this->app->instance(
            OwnerIdentityVerifier::class,
            new FakeOwnerIdentityVerifier($identity),
        );
    }

    private function useConfiguredFakeOwnerIdentity(int $authTime): void
    {
        config([
            'access_pairing.owner.firebase_project_id' => 'firebase-project',
            'access_pairing.owner.firebase_uid' => 'firebase-owner',
        ]);

        $this->useFakeOwnerIdentity(
            new VerifiedOwnerIdentity('firebase-project', 'firebase-owner', 'google.com', $authTime),
        );
    }

    private function postActivationBody(string $body, string $contentType = 'application/json'): TestResponse
    {
        $headers = $this->transformHeadersToServerVars([
            'Content-Type' => $contentType,
            'Authorization' => 'Bearer '.FakeOwnerIdentityVerifier::TEST_BEARER_TOKEN,
        ]);

        return $this->call(
            'POST',
            '/api/v1/owner/host-activations',
            [],
            $this->prepareCookiesForRequest(),
            [],
            $headers,
            $body,
        );
    }
}
