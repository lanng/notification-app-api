<?php

namespace Tests\Feature;

use App\Enums\AccessRole;
use App\Models\Installation;
use App\Models\Monitor;
use App\Models\MonitorMembership;
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

class InstallationAuthenticationTest extends TestCase
{
    use LazilyRefreshDatabase;

    public function test_returns_401_when_bearer_token_is_missing(): void
    {
        $this->getJson('/api/v1/installation')->assertUnauthorized();
    }

    public function test_returns_401_when_only_a_web_session_and_cookie_are_present(): void
    {
        $user = User::factory()->create();

        $this->actingAs($user, 'web')
            ->withSession(['_token' => 'session-csrf-token'])
            ->withCookie(config('session.cookie'), 'web-session-cookie')
            ->getJson('/api/v1/installation')
            ->assertUnauthorized()
            ->assertExactJson([
                'code' => 'unauthenticated',
                'message' => 'Autenticação necessária.',
            ]);
    }

    public function test_returns_only_the_authenticated_hosts_current_access_context(): void
    {
        $monitor = Monitor::factory()->create(['host_generation' => 3]);
        $installation = Installation::factory()->create(['label' => 'private installation label']);
        $membership = MonitorMembership::factory()
            ->host()
            ->for($monitor)
            ->for($installation)
            ->create(['generation' => 3]);
        $token = $installation->createToken('host-context', [])->plainTextToken;

        $query = http_build_query([
            'installationId' => (string) Str::uuid(),
            'monitorId' => (string) Str::uuid(),
            'membershipId' => (string) Str::uuid(),
            'role' => 'Support',
        ]);
        $response = $this->getJson('/api/v1/installation?'.$query, [
            'Authorization' => 'Bearer '.$token,
        ]);

        $response->assertOk()->assertExactJson([
            'data' => [
                'installationId' => $installation->id,
                'monitorId' => $monitor->id,
                'membershipId' => $membership->id,
                'role' => 'Host',
                'status' => 'Active',
                'monitorGeneration' => '3',
            ],
        ]);
    }

    public function test_reads_the_host_access_context_using_the_token_created_by_owner_activation(): void
    {
        $this->travelTo('2026-11-21 12:00:00 UTC');
        config([
            'access_pairing.owner.firebase_project_id' => 'firebase-project',
            'access_pairing.owner.firebase_uid' => 'firebase-owner',
        ]);
        $this->app->instance(
            OwnerIdentityVerifier::class,
            new FakeOwnerIdentityVerifier(
                new VerifiedOwnerIdentity('firebase-project', 'firebase-owner', 'google.com', now()->timestamp),
            ),
        );
        $activationResponse = $this->withToken(FakeOwnerIdentityVerifier::TEST_BEARER_TOKEN)
            ->postJson('/api/v1/owner/host-activations', [
                'confirmation' => true,
                'expectedGeneration' => '0',
            ]);
        $activationResponse->assertCreated();
        $hostData = $activationResponse->json('data');

        $this->getInstallationWithToken($hostData['accessToken'])->assertOk()->assertExactJson([
            'data' => [
                'installationId' => $hostData['installationId'],
                'monitorId' => $hostData['monitorId'],
                'membershipId' => $hostData['membershipId'],
                'role' => 'Host',
                'status' => 'Active',
                'monitorGeneration' => '1',
            ],
        ]);
    }

    public function test_reads_support_access_with_the_original_token_after_an_actual_host_swap(): void
    {
        $this->travelTo('2026-11-21 12:00:00 UTC');
        config([
            'access_pairing.owner.firebase_project_id' => 'firebase-project',
            'access_pairing.owner.firebase_uid' => 'firebase-owner',
        ]);
        $this->app->instance(
            OwnerIdentityVerifier::class,
            new FakeOwnerIdentityVerifier(
                new VerifiedOwnerIdentity('firebase-project', 'firebase-owner', 'google.com', now()->timestamp),
            ),
        );

        $firstActivationResponse = $this->withToken(FakeOwnerIdentityVerifier::TEST_BEARER_TOKEN)
            ->postJson('/api/v1/owner/host-activations', [
                'confirmation' => true,
                'expectedGeneration' => '0',
            ]);
        $firstActivationResponse->assertCreated();
        $firstHostData = $firstActivationResponse->json('data');
        $monitor = Monitor::query()->findOrFail($firstHostData['monitorId']);
        $supportInstallation = Installation::factory()->create();
        $supportMembership = MonitorMembership::factory()->for($monitor)->for($supportInstallation)->create([
            'role' => AccessRole::Support,
            'generation' => null,
        ]);
        $supportToken = $supportInstallation->createToken('persistent-support', ['support:monitor'])->plainTextToken;

        $swapResponse = $this->withToken(FakeOwnerIdentityVerifier::TEST_BEARER_TOKEN)
            ->postJson('/api/v1/owner/host-activations', [
                'confirmation' => true,
                'expectedGeneration' => '1',
            ]);
        $swapResponse->assertOk()->assertJsonPath('data.generation', '2');
        $this->app['auth']->forgetGuards();

        $this->getInstallationWithToken($supportToken)->assertOk()->assertExactJson([
            'data' => [
                'installationId' => $supportInstallation->id,
                'monitorId' => $monitor->id,
                'membershipId' => $supportMembership->id,
                'role' => 'Support',
                'status' => 'Active',
                'monitorGeneration' => '2',
            ],
        ]);
    }

    public function test_returns_403_for_a_valid_pending_installation_token_without_exposing_access_context(): void
    {
        $installation = Installation::factory()->create();
        $token = $installation->createToken('pending-context', ['pairing:pending'])->plainTextToken;

        $response = $this->getInstallationWithToken($token);

        $response->assertForbidden()->assertExactJson([
            'code' => 'access_forbidden',
            'message' => 'Acesso não permitido.',
        ]);
        $this->assertStringNotContainsString($installation->id, $response->getContent());
    }

    public function test_returns_current_support_access_without_treating_token_abilities_as_authority(): void
    {
        $monitor = Monitor::factory()->create(['host_generation' => 4]);
        $installation = Installation::factory()->create();
        $membership = MonitorMembership::factory()->for($monitor)->for($installation)->create([
            'role' => AccessRole::Support,
            'generation' => null,
        ]);
        $token = $installation->createToken('support-context', ['host:monitor'])->plainTextToken;
        $monitor->update(['host_generation' => 5]);

        $response = $this->getInstallationWithToken($token);

        $response->assertOk()->assertExactJson([
            'data' => [
                'installationId' => $installation->id,
                'monitorId' => $monitor->id,
                'membershipId' => $membership->id,
                'role' => 'Support',
                'status' => 'Active',
                'monitorGeneration' => '5',
            ],
        ]);
    }

    public function test_returns_403_for_a_valid_token_that_expires_one_second_in_the_future(): void
    {
        $this->travelTo('2026-11-21 12:00:00 UTC');
        $installation = Installation::factory()->create();
        $token = $installation->createToken(
            'expires-in-one-second',
            ['pairing:pending'],
            now('UTC')->addSecond(),
        )->plainTextToken;

        $response = $this->getInstallationWithToken($token);

        $response->assertForbidden()->assertExactJson([
            'code' => 'access_forbidden',
            'message' => 'Acesso não permitido.',
        ]);
    }

    public function test_returns_current_access_for_a_long_lived_token_without_global_expiration(): void
    {
        $host = $this->createCurrentHost();
        $this->travelTo('2036-11-21 12:00:00 UTC');

        $response = $this->getInstallationWithToken($host['token']);

        $response->assertOk()->assertJsonPath('data.installationId', $host['installation']->id);
    }

    public function test_returns_401_after_the_personal_access_token_is_revoked(): void
    {
        $installation = Installation::factory()->create();
        $token = $installation->createToken('revoked-token', ['pairing:pending']);
        $installation->tokens()->whereKey($token->accessToken->getKey())->delete();

        $this->getInstallationWithToken($token->plainTextToken)->assertUnauthorized()->assertExactJson([
            'code' => 'unauthenticated',
            'message' => 'Autenticação necessária.',
        ]);
    }

    public function test_returns_403_for_a_host_membership_from_an_old_monitor_generation(): void
    {
        $host = $this->createCurrentHost();
        $host['monitor']->update(['host_generation' => 4]);

        $this->getInstallationWithToken($host['token'])->assertForbidden()->assertExactJson([
            'code' => 'access_forbidden',
            'message' => 'Acesso não permitido.',
        ]);
    }

    public function test_returns_403_for_a_revoked_membership_while_its_token_remains_valid(): void
    {
        $host = $this->createCurrentHost();
        $host['membership']->update(['revoked_at' => now()]);

        $this->getInstallationWithToken($host['token'])->assertForbidden()->assertExactJson([
            'code' => 'access_forbidden',
            'message' => 'Acesso não permitido.',
        ]);
    }

    public function test_returns_403_when_an_installation_has_multiple_current_memberships(): void
    {
        $host = $this->createCurrentHost();
        $otherMonitor = Monitor::factory()->create(['host_generation' => 7]);
        MonitorMembership::factory()->for($otherMonitor)->for($host['installation'])->create([
            'role' => AccessRole::Support,
            'generation' => null,
        ]);

        $this->getInstallationWithToken($host['token'])->assertForbidden()->assertExactJson([
            'code' => 'access_forbidden',
            'message' => 'Acesso não permitido.',
        ]);
    }

    public function test_rechecks_the_current_membership_on_each_authenticated_request(): void
    {
        $host = $this->createCurrentHost();
        $this->getInstallationWithToken($host['token'])->assertOk();
        $host['membership']->update(['revoked_at' => now()]);
        $this->app['auth']->forgetGuards();

        $this->getInstallationWithToken($host['token'])->assertForbidden()->assertExactJson([
            'code' => 'access_forbidden',
            'message' => 'Acesso não permitido.',
        ]);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function invalidBearerTokens(): array
    {
        return [
            'unknown token' => ['invented-bearer-token'],
            'nondecimal identifier' => ['not-an-id|secret'],
            'empty secret' => ['1|'],
            'zero identifier' => ['0|secret'],
            'identifier above signed integer range' => ['9223372036854775808|secret'],
        ];
    }

    #[DataProvider('invalidBearerTokens')]
    public function test_returns_401_for_an_invalid_bearer_token(string $token): void
    {
        $this->getInstallationWithToken($token)->assertUnauthorized()->assertExactJson([
            'code' => 'unauthenticated',
            'message' => 'Autenticação necessária.',
        ]);
    }

    public function test_returns_401_when_a_real_token_identifier_has_the_wrong_secret(): void
    {
        $host = $this->createCurrentHost();
        [$tokenId, $secret] = explode('|', $host['token'], 2);

        $this->getInstallationWithToken($tokenId.'|'.$secret.'wrong')
            ->assertUnauthorized()
            ->assertExactJson([
                'code' => 'unauthenticated',
                'message' => 'Autenticação necessária.',
            ]);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function nonInstallationTokenableTypes(): array
    {
        return [
            'user account with an incompatible bigint key' => [User::class],
            'unknown morph class' => ['Untrusted\\Tokenable'],
        ];
    }

    #[DataProvider('nonInstallationTokenableTypes')]
    public function test_returns_401_for_a_valid_token_with_a_non_installation_principal(
        string $tokenableType,
    ): void {
        $secret = 'synthetic-valid-pat-secret';
        $personalAccessToken = new PersonalAccessToken;
        $personalAccessToken->forceFill([
            'tokenable_type' => $tokenableType,
            'tokenable_id' => (string) Str::uuid(),
            'name' => 'wrong-principal',
            'token' => hash('sha256', $secret),
            'abilities' => ['*'],
        ]);
        $personalAccessToken->save();

        $this->getInstallationWithToken($personalAccessToken->getKey().'|'.$secret)
            ->assertUnauthorized()
            ->assertExactJson([
                'code' => 'access_unauthenticated',
                'message' => 'A credencial não é válida.',
            ]);
    }

    public function test_returns_401_for_an_installation_token_without_a_matching_installation_record(): void
    {
        $secret = 'synthetic-missing-installation-secret';
        $personalAccessToken = new PersonalAccessToken;
        $personalAccessToken->forceFill([
            'tokenable_type' => Installation::class,
            'tokenable_id' => (string) Str::uuid(),
            'name' => 'missing-installation',
            'token' => hash('sha256', $secret),
            'abilities' => ['*'],
        ]);
        $personalAccessToken->save();

        $this->getInstallationWithToken($personalAccessToken->getKey().'|'.$secret)
            ->assertUnauthorized()
            ->assertExactJson([
                'code' => 'unauthenticated',
                'message' => 'Autenticação necessária.',
            ]);
    }

    public function test_returns_401_when_a_personal_token_expires_at_the_current_instant(): void
    {
        $this->travelTo('2026-11-21 12:00:00 UTC');
        $installation = Installation::factory()->create();
        $token = $installation->createToken(
            'expires-now',
            ['pairing:pending'],
            now('UTC'),
        )->plainTextToken;

        $response = $this->getInstallationWithToken($token);

        $response->assertUnauthorized()->assertExactJson([
            'code' => 'unauthenticated',
            'message' => 'Autenticação necessária.',
        ]);
    }

    public function test_returns_401_when_a_personal_token_expired_one_second_ago(): void
    {
        $this->travelTo('2026-11-21 12:00:00 UTC');
        $installation = Installation::factory()->create();
        $token = $installation->createToken(
            'expired-one-second-ago',
            ['pairing:pending'],
            now('UTC')->subSecond(),
        )->plainTextToken;

        $this->getInstallationWithToken($token)->assertUnauthorized()->assertExactJson([
            'code' => 'unauthenticated',
            'message' => 'Autenticação necessária.',
        ]);
    }

    public function test_global_sanctum_expiration_still_rejects_a_token_without_individual_expiry(): void
    {
        $this->travelTo('2026-11-21 12:00:00 UTC');
        $host = $this->createCurrentHost();
        [$tokenId] = explode('|', $host['token'], 2);
        $personalAccessToken = PersonalAccessToken::query()->findOrFail((int) $tokenId);
        $personalAccessToken->created_at = now('UTC')->subMinutes(2);
        $personalAccessToken->save();
        $this->assertNull($personalAccessToken->fresh()->expires_at);

        $originalExpiration = config('sanctum.expiration');
        config(['sanctum.expiration' => 1]);

        try {
            $this->app['auth']->forgetGuards();
            $this->getInstallationWithToken($host['token'])->assertUnauthorized()->assertExactJson([
                'code' => 'unauthenticated',
                'message' => 'Autenticação necessária.',
            ]);
        } finally {
            config(['sanctum.expiration' => $originalExpiration]);
            $this->app['auth']->forgetGuards();
        }
    }

    /**
     * @return array{installation: Installation, monitor: Monitor, membership: MonitorMembership, token: string}
     */
    private function createCurrentHost(): array
    {
        $monitor = Monitor::factory()->create(['host_generation' => 3]);
        $installation = Installation::factory()->create();
        $membership = MonitorMembership::factory()
            ->host()
            ->for($monitor)
            ->for($installation)
            ->create(['generation' => 3]);
        $token = $installation->createToken('host-context', [])->plainTextToken;

        return compact('installation', 'monitor', 'membership', 'token');
    }

    private function getInstallationWithToken(string $token): TestResponse
    {
        return $this->getJson('/api/v1/installation', [
            'Authorization' => 'Bearer '.$token,
        ]);
    }
}
