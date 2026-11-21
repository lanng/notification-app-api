<?php

namespace Tests\Support;

use App\Enums\AccessRole;
use App\Models\Installation;
use App\Models\Monitor;
use App\Models\MonitorMembership;
use App\Support\AccessAndPairing\OwnerIdentityVerifier;
use App\Support\AccessAndPairing\VerifiedOwnerIdentity;
use Illuminate\Testing\TestResponse;
use Laravel\Sanctum\PersonalAccessToken;
use LogicException;
use Tests\TestCase;

final class AccessAndPairingFixtures
{
    public function __construct(private readonly TestCase $testCase) {}

    /**
     * @return array{
     *     monitor: Monitor,
     *     installation: Installation,
     *     membership: MonitorMembership,
     *     token: string,
     *     accessToken: PersonalAccessToken
     * }
     */
    public function createHost(
        string $firebaseUid = 'fixture-owner',
        string $remoteAddress = '192.0.2.10',
    ): array {
        $firebaseProjectId = 'fixture-project';
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

        $response = $this->requestJson(
            'POST',
            '/api/v1/owner/host-activations',
            '{"confirmation":true,"expectedGeneration":"0"}',
            ['Authorization' => 'Bearer '.FakeOwnerIdentityVerifier::TEST_BEARER_TOKEN],
            $remoteAddress,
        );
        $response->assertCreated();

        $data = $response->json('data');
        $monitor = Monitor::query()->findOrFail($data['monitorId']);
        $installation = Installation::query()->findOrFail($data['installationId']);
        $membership = MonitorMembership::query()->findOrFail($data['membershipId']);
        $accessToken = PersonalAccessToken::findToken($data['accessToken']);

        if (! $accessToken instanceof PersonalAccessToken) {
            throw new LogicException('The host activation fixture did not create its personal access token.');
        }

        return [
            'monitor' => $monitor,
            'installation' => $installation,
            'membership' => $membership,
            'token' => $data['accessToken'],
            'accessToken' => $accessToken,
        ];
    }

    /**
     * @return array{
     *     installation: Installation,
     *     membership: MonitorMembership,
     *     token: string,
     *     accessToken: PersonalAccessToken
     * }
     */
    public function createSupportInstallation(Monitor $monitor): array
    {
        $installation = Installation::factory()->create();
        $membership = MonitorMembership::factory()
            ->for($monitor)
            ->for($installation)
            ->create([
                'role' => AccessRole::Support,
                'generation' => null,
            ]);
        $token = $installation->createToken('fixture-support', ['support:monitor']);

        return [
            'installation' => $installation,
            'membership' => $membership,
            'token' => $token->plainTextToken,
            'accessToken' => $token->accessToken,
        ];
    }

    /**
     * @param  array<string, string>  $headers
     */
    public function requestJson(
        string $method,
        string $uri,
        string $body = '',
        array $headers = [],
        string $remoteAddress = '192.0.2.20',
    ): TestResponse {
        $server = [
            'CONTENT_TYPE' => 'application/json',
            'HTTP_ACCEPT' => 'application/json',
            'REMOTE_ADDR' => $remoteAddress,
        ];

        foreach ($headers as $name => $value) {
            $server['HTTP_'.strtoupper(str_replace('-', '_', $name))] = $value;
        }

        app('auth')->forgetGuards();

        return $this->testCase->call($method, $uri, [], [], [], $server, $body);
    }
}
