<?php

namespace Tests\Feature;

use App\Enums\AccessRole;
use App\Models\Installation;
use App\Models\Monitor;
use App\Models\MonitorMembership;
use App\Models\User;
use App\Support\AccessAndPairing\FirebaseVerificationClient;
use Illuminate\Foundation\Testing\LazilyRefreshDatabase;
use Laravel\Sanctum\PersonalAccessToken;
use Tests\Support\FirebaseIdentityFixtures;
use Tests\TestCase;

class FirebaseOwnerIdentityTest extends TestCase
{
    use LazilyRefreshDatabase;

    public function test_enabled_google_identity_discovers_an_empty_monitor_without_writing_records(): void
    {
        $this->travelTo('2026-11-22 12:00:00 UTC');
        $requests = [];
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
                FirebaseIdentityFixtures::serviceAccount(),
                FirebaseIdentityFixtures::transport($requests),
            ),
        );
        $usersBefore = User::query()->count();
        $monitorsBefore = Monitor::query()->count();
        $installationsBefore = Installation::query()->count();
        $membershipsBefore = MonitorMembership::query()->count();

        $response = $this->get('/api/v1/owner/monitor', [
            'Authorization' => 'Bearer '.FirebaseIdentityFixtures::idToken(),
            'Accept' => 'application/json',
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
        $this->assertSame($membershipsBefore, MonitorMembership::query()->count());
        $this->assertCount(5, $requests);
        $certificateUrls = array_values(array_map(
            static fn (array $request): string => $request['url'],
            array_filter(
                $requests,
                static fn (array $request): bool => str_contains($request['url'], 'www.googleapis.com/'),
            ),
        ));
        $this->assertSame([
            'https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com',
            'https://www.googleapis.com/oauth2/v1/certs',
            'https://www.googleapis.com/identitytoolkit/v3/relyingparty/publicKeys',
        ], $certificateUrls);
        $this->assertSame([3.0, 3.0, 3.0, 3.0, 3.0], array_column($requests, 'connect_timeout'));
        $this->assertSame([5.0, 5.0, 5.0, 5.0, 5.0], array_column($requests, 'timeout'));
        $this->assertCount(1, array_filter(
            $requests,
            static fn (array $request): bool => str_contains($request['url'], 'oauth2.googleapis.com/token'),
        ));
        $this->assertCount(1, array_filter(
            $requests,
            static fn (array $request): bool => str_contains($request['url'], 'accounts:lookup'),
        ));
    }

    public function test_enabled_recent_google_identity_activates_a_host_with_a_one_time_token(): void
    {
        $this->travelTo('2026-11-22 12:00:00 UTC');
        $requests = [];
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
                FirebaseIdentityFixtures::serviceAccount(),
                FirebaseIdentityFixtures::transport($requests),
            ),
        );
        $usersBefore = User::query()->count();
        $monitorsBefore = Monitor::query()->count();
        $installationsBefore = Installation::query()->count();
        $membershipsBefore = MonitorMembership::query()->count();
        $tokensBefore = PersonalAccessToken::query()->count();

        $response = $this->postJson('/api/v1/owner/host-activations', [
            'confirmation' => true,
            'expectedGeneration' => '0',
        ], [
            'Authorization' => 'Bearer '.FirebaseIdentityFixtures::idToken(),
        ]);

        $response->assertCreated();
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
        $this->assertSame('Host', $data['role']);
        $this->assertSame('1', $data['generation']);
        $this->assertTrue($data['requiresReference']);
        $this->assertSame(1, User::query()->count() - $usersBefore);
        $this->assertSame(1, Monitor::query()->count() - $monitorsBefore);
        $this->assertSame(1, Installation::query()->count() - $installationsBefore);
        $this->assertSame(1, MonitorMembership::query()->count() - $membershipsBefore);
        $this->assertSame(1, PersonalAccessToken::query()->count() - $tokensBefore);

        $user = User::query()->where('firebase_project_id', 'firebase-project')
            ->where('firebase_uid', 'firebase-owner')
            ->firstOrFail();
        $monitor = Monitor::query()->findOrFail($data['monitorId']);
        $installation = Installation::query()->findOrFail($data['installationId']);
        $membership = MonitorMembership::query()->findOrFail($data['membershipId']);
        $accessToken = PersonalAccessToken::findToken($data['accessToken']);

        $this->assertSame($user->id, $monitor->user_id);
        $this->assertSame(1, $monitor->host_generation);
        $this->assertTrue($monitor->requires_reference);
        $this->assertNull($installation->label);
        $this->assertSame($installation->id, $membership->installation_id);
        $this->assertSame(AccessRole::Host, $membership->role);
        $this->assertSame(1, $membership->generation);
        $this->assertNotNull($accessToken);
        $this->assertSame(Installation::class, $accessToken->tokenable_type);
        $this->assertSame($installation->id, $accessToken->tokenable_id);
        $this->assertSame(['host:monitor'], $accessToken->abilities);
        $this->assertCount(1, array_filter(
            $requests,
            static fn (array $request): bool => str_contains($request['url'], 'accounts:lookup'),
        ));
        $this->assertCount(1, array_filter(
            $requests,
            static fn (array $request): bool => str_contains($request['url'], 'oauth2.googleapis.com/token'),
        ));
    }
}
