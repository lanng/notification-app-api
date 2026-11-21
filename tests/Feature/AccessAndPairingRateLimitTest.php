<?php

namespace Tests\Feature;

use App\Models\Installation;
use App\Models\Invitation;
use App\Models\PairingRequest;
use App\Support\AccessAndPairing\OwnerIdentityVerifier;
use App\Support\AccessAndPairing\VerifiedOwnerIdentity;
use Illuminate\Foundation\Testing\LazilyRefreshDatabase;
use Illuminate\Testing\TestResponse;
use Tests\Support\AccessAndPairingFixtures;
use Tests\Support\FakeOwnerIdentityVerifier;
use Tests\TestCase;

class AccessAndPairingRateLimitTest extends TestCase
{
    use LazilyRefreshDatabase;

    public function test_public_redemption_ip_limit_counts_malformed_json_and_ignores_forwarded_ips(): void
    {
        $fixtures = new AccessAndPairingFixtures($this);

        for ($attempt = 1; $attempt <= 10; $attempt++) {
            $response = $fixtures->requestJson(
                'POST',
                '/api/v1/pairing-requests',
                '{',
                ['X-Forwarded-For' => '203.0.113.'.$attempt],
                '198.51.100.50',
            );
            $response->assertBadRequest()->assertJsonPath('code', 'malformed_json');
        }

        $eleventhResponse = $fixtures->requestJson(
            'POST',
            '/api/v1/pairing-requests',
            '{',
            ['X-Forwarded-For' => '203.0.113.99'],
            '198.51.100.50',
        );

        $this->assertRateLimited($eleventhResponse);
        $this->assertSame(0, Installation::query()->count());
        $this->assertSame(0, PairingRequest::query()->count());
    }

    public function test_public_redemption_secret_hmac_limit_is_shared_across_direct_ips_and_counts_consumed_attempts(): void
    {
        $this->travelTo('2026-11-21 12:00:00 UTC');
        $fixtures = new AccessAndPairingFixtures($this);
        $host = $fixtures->createHost();
        $issued = $fixtures->requestJson(
            'POST',
            "/api/v1/monitors/{$host['monitor']->id}/invitations",
            '{}',
            ['Authorization' => 'Bearer '.$host['token']],
        );
        $secret = $issued->json('data.invitationSecret');
        $body = json_encode(['invitationSecret' => $secret], JSON_THROW_ON_ERROR);

        $firstResponse = $fixtures->requestJson(
            'POST',
            '/api/v1/pairing-requests',
            $body,
            remoteAddress: '198.51.100.60',
        );
        $firstResponse->assertCreated();
        $installationsAfterFirstAttempt = Installation::query()->count();

        for ($attempt = 1; $attempt <= 4; $attempt++) {
            $response = $fixtures->requestJson(
                'POST',
                '/api/v1/pairing-requests',
                $body,
                remoteAddress: '198.51.100.'.(60 + $attempt),
            );
            $response->assertGone()->assertJsonPath('code', 'invitation_unavailable');
        }

        $sixthResponse = $fixtures->requestJson(
            'POST',
            '/api/v1/pairing-requests',
            $body,
            remoteAddress: '198.51.100.65',
        );

        $this->assertRateLimited($sixthResponse);
        $this->assertSame($installationsAfterFirstAttempt, Installation::query()->count());
        $this->assertSame(1, PairingRequest::query()->count());
    }

    public function test_public_redemption_returns_429_after_five_attempts_for_a_secret_even_when_other_payload_fields_are_invalid(): void
    {
        $this->travelTo('2026-11-21 12:00:00 UTC');
        $fixtures = new AccessAndPairingFixtures($this);
        $host = $fixtures->createHost();
        $issued = $fixtures->requestJson(
            'POST',
            "/api/v1/monitors/{$host['monitor']->id}/invitations",
            '{}',
            ['Authorization' => 'Bearer '.$host['token']],
        );
        $body = json_encode([
            'invitationSecret' => $issued->json('data.invitationSecret'),
            'unexpected' => true,
        ], JSON_THROW_ON_ERROR);

        for ($attempt = 1; $attempt <= 5; $attempt++) {
            $response = $fixtures->requestJson(
                'POST',
                '/api/v1/pairing-requests',
                $body,
                remoteAddress: '198.51.100.'.(170 + $attempt),
            );
            $response->assertUnprocessable()->assertJsonPath('code', 'invalid_payload');
        }

        $sixthResponse = $fixtures->requestJson(
            'POST',
            '/api/v1/pairing-requests',
            $body,
            remoteAddress: '198.51.100.176',
        );

        $this->assertRateLimited($sixthResponse);
        $this->assertSame(0, PairingRequest::query()->count());
    }

    public function test_owner_ip_limit_is_shared_by_owner_read_and_activation_before_the_disabled_verifier(): void
    {
        $fixtures = new AccessAndPairingFixtures($this);

        for ($attempt = 1; $attempt <= 10; $attempt++) {
            $response = $attempt <= 5
                ? $fixtures->requestJson(
                    'GET',
                    '/api/v1/owner/monitor',
                    remoteAddress: '198.51.100.70',
                    headers: ['X-Forwarded-For' => '203.0.113.'.$attempt],
                )
                : $fixtures->requestJson(
                    'POST',
                    '/api/v1/owner/host-activations',
                    '{}',
                    remoteAddress: '198.51.100.70',
                    headers: ['X-Forwarded-For' => '203.0.113.'.$attempt],
                );

            $response->assertServiceUnavailable()
                ->assertJsonPath('code', 'identity_verification_unavailable');
        }

        $eleventhResponse = $fixtures->requestJson(
            'GET',
            '/api/v1/owner/monitor',
            remoteAddress: '198.51.100.70',
            headers: ['X-Forwarded-For' => '203.0.113.99'],
        );

        $this->assertRateLimited($eleventhResponse);
    }

    public function test_owner_verified_identity_hmac_limit_is_shared_across_routes_and_direct_ips(): void
    {
        $this->travelTo('2026-11-21 12:00:00 UTC');
        config([
            'access_pairing.owner.firebase_project_id' => 'rate-limit-project',
            'access_pairing.owner.firebase_uid' => 'rate-limit-owner',
        ]);
        app()->instance(
            OwnerIdentityVerifier::class,
            new FakeOwnerIdentityVerifier(
                new VerifiedOwnerIdentity(
                    'rate-limit-project',
                    'rate-limit-owner',
                    'google.com',
                    now('UTC')->getTimestamp(),
                ),
            ),
        );
        $fixtures = new AccessAndPairingFixtures($this);
        $generation = '0';

        for ($attempt = 1; $attempt <= 10; $attempt++) {
            $headers = ['Authorization' => 'Bearer '.FakeOwnerIdentityVerifier::TEST_BEARER_TOKEN];
            $remoteAddress = '198.51.100.'.(80 + $attempt);

            if ($attempt <= 5) {
                $response = $fixtures->requestJson(
                    'GET',
                    '/api/v1/owner/monitor',
                    headers: $headers,
                    remoteAddress: $remoteAddress,
                );
                $response->assertOk();
            } else {
                $response = $fixtures->requestJson(
                    'POST',
                    '/api/v1/owner/host-activations',
                    json_encode([
                        'confirmation' => true,
                        'expectedGeneration' => $generation,
                    ], JSON_THROW_ON_ERROR),
                    $headers,
                    $remoteAddress,
                );
                $this->assertContains($response->getStatusCode(), [200, 201]);
                $generation = $response->json('data.generation');
            }
        }

        $eleventhResponse = $fixtures->requestJson(
            'GET',
            '/api/v1/owner/monitor',
            headers: ['Authorization' => 'Bearer '.FakeOwnerIdentityVerifier::TEST_BEARER_TOKEN],
            remoteAddress: '198.51.100.100',
        );

        $this->assertRateLimited($eleventhResponse);
    }

    public function test_invitation_issuance_limit_is_per_authorized_monitor_across_rotated_pat_and_ips(): void
    {
        $fixtures = new AccessAndPairingFixtures($this);
        $host = $fixtures->createHost();

        for ($attempt = 1; $attempt <= 10; $attempt++) {
            $token = $attempt === 1
                ? $host['token']
                : $host['installation']->createToken('rotated-host-'.$attempt, ['host:monitor'])->plainTextToken;
            $response = $fixtures->requestJson(
                'POST',
                "/api/v1/monitors/{$host['monitor']->id}/invitations",
                '{}',
                ['Authorization' => 'Bearer '.$token],
                '198.51.100.'.(110 + $attempt),
            );
            $response->assertCreated();
        }

        $installationCount = Invitation::query()
            ->where('monitor_id', $host['monitor']->id)
            ->count();
        $eleventhToken = $host['installation']
            ->createToken('rotated-host-eleventh', ['host:monitor'])
            ->plainTextToken;
        $eleventhResponse = $fixtures->requestJson(
            'POST',
            "/api/v1/monitors/{$host['monitor']->id}/invitations",
            '{}',
            ['Authorization' => 'Bearer '.$eleventhToken],
            '198.51.100.121',
        );

        $this->assertRateLimited($eleventhResponse);
        $this->assertSame($installationCount, Invitation::query()
            ->where('monitor_id', $host['monitor']->id)
            ->count());
    }

    public function test_pairing_poll_limit_is_per_installation_across_rotated_pat_and_ips(): void
    {
        $this->travelTo('2026-11-21 12:00:00 UTC');
        $fixtures = new AccessAndPairingFixtures($this);
        $host = $fixtures->createHost();
        $candidate = Installation::factory()->create();
        $invitation = Invitation::factory()->create([
            'monitor_id' => $host['monitor']->id,
            'issuing_installation_id' => $host['installation']->id,
            'issuing_generation' => 1,
            'consumed_at' => now('UTC'),
        ]);
        PairingRequest::factory()->pending()->create([
            'monitor_id' => $host['monitor']->id,
            'invitation_id' => $invitation->id,
            'installation_id' => $candidate->id,
            'request_expires_at' => now('UTC')->addMinutes(15),
        ]);

        for ($attempt = 1; $attempt <= 30; $attempt++) {
            $token = $candidate
                ->createToken('rotated-candidate-'.$attempt, ['pairing:pending'])
                ->plainTextToken;
            $response = $fixtures->requestJson(
                'GET',
                '/api/v1/pairing-requests/current',
                headers: ['Authorization' => 'Bearer '.$token],
                remoteAddress: '198.51.100.'.(130 + $attempt),
            );
            $response->assertOk();
        }

        $eleventhPat = $candidate
            ->createToken('rotated-candidate-31', ['pairing:pending'])
            ->plainTextToken;
        $thirtyFirstResponse = $fixtures->requestJson(
            'GET',
            '/api/v1/pairing-requests/current',
            headers: ['Authorization' => 'Bearer '.$eleventhPat],
            remoteAddress: '198.51.100.161',
        );

        $this->assertRateLimited($thirtyFirstResponse);
    }

    private function assertRateLimited(TestResponse $response): void
    {
        $response->assertTooManyRequests()->assertExactJson([
            'code' => 'rate_limited',
            'message' => 'Limite de tentativas atingido.',
        ]);
        $retryAfter = $response->headers->get('Retry-After');
        $this->assertIsNumeric($retryAfter);
        $this->assertGreaterThan(0, (int) $retryAfter);
    }
}
