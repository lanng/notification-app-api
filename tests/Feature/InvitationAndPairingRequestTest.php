<?php

namespace Tests\Feature;

use App\Enums\AccessRole;
use App\Enums\PairingRequestStatus;
use App\Models\Installation;
use App\Models\Invitation;
use App\Models\Monitor;
use App\Models\MonitorMembership;
use App\Models\PairingRequest;
use Illuminate\Foundation\Testing\LazilyRefreshDatabase;
use Illuminate\Support\Str;
use Laravel\Sanctum\PersonalAccessToken;
use PHPUnit\Framework\Attributes\DataProvider;
use Tests\Support\AccessAndPairingFixtures;
use Tests\TestCase;

class InvitationAndPairingRequestTest extends TestCase
{
    use LazilyRefreshDatabase;

    public function test_current_host_issues_one_time_invitation_secret_with_a_fifteen_minute_expiry(): void
    {
        $this->travelTo('2026-11-21 12:00:00 UTC');
        $host = (new AccessAndPairingFixtures($this))->createHost();
        $monitor = $host['monitor'];

        $response = $this->call(
            'POST',
            "/api/v1/monitors/{$monitor->id}/invitations",
            [],
            [],
            [],
            $this->transformHeadersToServerVars([
                'Content-Type' => 'application/json',
                'Authorization' => 'Bearer '.$host['token'],
            ]),
            '{}',
        );

        $response->assertCreated();
        $data = $response->json('data');
        $this->assertSame(['id', 'invitationSecret', 'createdAt', 'expiresAt'], array_keys($data));
        $this->assertTrue(Str::isUuid($data['id']));
        $this->assertSame(43, strlen($data['invitationSecret']));
        $this->assertSame(1, preg_match('/\A[A-Za-z0-9_-]{43}\z/', $data['invitationSecret']));
        $this->assertSame(1795262400000, $data['createdAt']);
        $this->assertSame(1795263300000, $data['expiresAt']);
        $this->assertDatabaseHas('invitations', [
            'id' => $data['id'],
            'monitor_id' => $monitor->id,
            'issuing_installation_id' => $host['installation']->id,
            'issuing_generation' => 1,
            'secret_hash' => hash('sha256', $data['invitationSecret']),
        ]);
        $this->assertDatabaseMissing('invitations', ['secret_hash' => $data['invitationSecret']]);
    }

    public function test_host_lists_only_available_invitations_with_explicit_redacted_fields(): void
    {
        $this->travelTo('2026-11-21 12:00:00 UTC');
        $host = (new AccessAndPairingFixtures($this))->createHost();
        $monitor = $host['monitor'];

        $olderInvitation = Invitation::factory()->create([
            'monitor_id' => $monitor->id,
            'issuing_installation_id' => $host['installation']->id,
            'issuing_generation' => 1,
            'expires_at' => now('UTC')->addMinutes(15),
        ]);
        $olderInvitation->created_at = now('UTC')->subMinutes(2);
        $olderInvitation->save();
        $newerInvitation = Invitation::factory()->create([
            'monitor_id' => $monitor->id,
            'issuing_installation_id' => $host['installation']->id,
            'issuing_generation' => 1,
            'expires_at' => now('UTC')->addMinutes(15),
        ]);
        $newerInvitation->created_at = now('UTC')->subMinute();
        $newerInvitation->save();
        Invitation::factory()->create([
            'monitor_id' => $monitor->id,
            'issuing_installation_id' => $host['installation']->id,
            'issuing_generation' => 1,
            'expires_at' => now('UTC')->subSecond(),
        ]);
        Invitation::factory()->create([
            'monitor_id' => $monitor->id,
            'issuing_installation_id' => $host['installation']->id,
            'issuing_generation' => 1,
            'consumed_at' => now('UTC'),
        ]);
        Invitation::factory()->create([
            'monitor_id' => $monitor->id,
            'issuing_installation_id' => $host['installation']->id,
            'issuing_generation' => 1,
            'revoked_at' => now('UTC'),
        ]);
        Invitation::factory()->create([
            'monitor_id' => $monitor->id,
            'issuing_installation_id' => $host['installation']->id,
            'issuing_generation' => 0,
            'expires_at' => now('UTC')->addMinutes(15),
        ]);

        $response = $this->getJson(
            "/api/v1/monitors/{$monitor->id}/invitations",
            ['Authorization' => 'Bearer '.$host['token']],
        );

        $response->assertOk()->assertExactJson([
            'data' => [
                [
                    'id' => $olderInvitation->id,
                    'status' => 'Available',
                    'createdAt' => 1795262280000,
                    'expiresAt' => 1795263300000,
                ],
                [
                    'id' => $newerInvitation->id,
                    'status' => 'Available',
                    'createdAt' => 1795262340000,
                    'expiresAt' => 1795263300000,
                ],
            ],
        ]);
        $this->assertStringNotContainsString('secret_hash', $response->getContent());
        $this->assertStringNotContainsString($olderInvitation->secret_hash, $response->getContent());
    }

    public function test_host_can_cancel_an_unused_invitation_repeatedly_with_no_content(): void
    {
        $this->travelTo('2026-11-21 12:00:00 UTC');
        $fixtures = new AccessAndPairingFixtures($this);
        $host = $fixtures->createHost();
        $invitationResponse = $fixtures->requestJson(
            'POST',
            "/api/v1/monitors/{$host['monitor']->id}/invitations",
            '{}',
            ['Authorization' => 'Bearer '.$host['token']],
        );
        $invitationResponse->assertCreated();
        $invitationId = $invitationResponse->json('data.id');

        $firstCancellation = $fixtures->requestJson(
            'DELETE',
            "/api/v1/monitors/{$host['monitor']->id}/invitations/{$invitationId}",
            '{}',
            ['Authorization' => 'Bearer '.$host['token']],
        );
        $firstCancellation->assertNoContent();
        $revokedAt = Invitation::query()->findOrFail($invitationId)->revoked_at;

        $repeatCancellation = $fixtures->requestJson(
            'DELETE',
            "/api/v1/monitors/{$host['monitor']->id}/invitations/{$invitationId}",
            '{}',
            ['Authorization' => 'Bearer '.$host['token']],
        );
        $repeatCancellation->assertNoContent();

        $this->assertNotNull($revokedAt);
        $this->assertSame($revokedAt->toISOString(), Invitation::query()->findOrFail($invitationId)->revoked_at->toISOString());
    }

    public function test_invitation_listing_is_ordered_and_capped_at_fifty_without_serializing_secrets(): void
    {
        $this->travelTo('2026-11-21 12:00:00 UTC');
        $host = (new AccessAndPairingFixtures($this))->createHost();
        $invitations = collect(range(0, 52))
            ->map(fn (int $index): Invitation => Invitation::factory()->create([
                'monitor_id' => $host['monitor']->id,
                'issuing_installation_id' => $host['installation']->id,
                'issuing_generation' => 1,
                'expires_at' => now('UTC')->addMinutes(15),
                'created_at' => now('UTC')->addSeconds($index),
            ]))
            ->sortBy('created_at')
            ->take(50)
            ->values();

        $response = $this->getJson(
            "/api/v1/monitors/{$host['monitor']->id}/invitations",
            ['Authorization' => 'Bearer '.$host['token']],
        );

        $response->assertOk();
        $listed = $response->json('data');
        $this->assertCount(50, $listed);
        $this->assertSame($invitations->pluck('id')->all(), array_column($listed, 'id'));
        $this->assertSame(
            ['id', 'status', 'createdAt', 'expiresAt'],
            array_keys($listed[0]),
        );
        $this->assertStringNotContainsString('secret_hash', $response->getContent());
        $this->assertStringNotContainsString($invitations->first()->secret_hash, $response->getContent());
    }

    public function test_support_cannot_use_a_malformed_monitor_id_to_probe_invitation_routes(): void
    {
        $host = (new AccessAndPairingFixtures($this))->createHost();
        $support = (new AccessAndPairingFixtures($this))->createSupportInstallation($host['monitor']);
        $fixtures = new AccessAndPairingFixtures($this);

        $response = $fixtures->requestJson(
            'DELETE',
            '/api/v1/monitors/not-a-uuid/invitations/not-a-uuid',
            '{}',
            ['Authorization' => 'Bearer '.$support['token']],
        );

        $response->assertForbidden()->assertJsonPath('code', 'access_forbidden');
    }

    public function test_current_host_gets_the_same_not_found_for_a_foreign_monitor_before_invitation_id_validation(): void
    {
        $fixtures = new AccessAndPairingFixtures($this);
        $host = $fixtures->createHost();
        $foreignMonitor = Monitor::factory()->create();

        $response = $fixtures->requestJson(
            'DELETE',
            "/api/v1/monitors/{$foreignMonitor->id}/invitations/not-a-uuid",
            '{}',
            ['Authorization' => 'Bearer '.$host['token']],
        );

        $response->assertNotFound()->assertJsonPath('code', 'resource_not_found');
    }

    public function test_cancelling_a_consumed_invitation_conflicts_without_touching_its_pending_request_or_token(): void
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
            'expires_at' => now('UTC')->addMinutes(15),
        ]);
        $pairingRequest = PairingRequest::factory()->pending()->create([
            'monitor_id' => $host['monitor']->id,
            'invitation_id' => $invitation->id,
            'installation_id' => $candidate->id,
            'request_expires_at' => now('UTC')->addMinutes(15),
        ]);
        $candidateToken = $candidate->createToken(
            'pending-pairing',
            ['pairing:pending'],
            now('UTC')->addMinutes(15),
        );

        $response = $fixtures->requestJson(
            'DELETE',
            "/api/v1/monitors/{$host['monitor']->id}/invitations/{$invitation->id}",
            '{}',
            ['Authorization' => 'Bearer '.$host['token']],
        );

        $response->assertConflict()->assertJsonPath('code', 'invitation_already_consumed');
        $this->assertSame(PairingRequestStatus::Pending, $pairingRequest->fresh()->status);
        $this->assertNull($pairingRequest->fresh()->decided_at);
        $this->assertNotNull(PersonalAccessToken::findToken($candidateToken->plainTextToken));
    }

    public function test_public_redemption_creates_a_pending_request_and_returns_the_one_time_token(): void
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
        $issued->assertCreated();
        $secret = $issued->json('data.invitationSecret');

        $response = $fixtures->requestJson(
            'POST',
            '/api/v1/pairing-requests',
            json_encode([
                'invitationSecret' => $secret,
                'installationLabel' => str_repeat('é', 128),
            ], JSON_THROW_ON_ERROR),
            remoteAddress: '198.51.100.31',
        );

        $response->assertCreated();
        $data = $response->json('data');
        $this->assertSame([
            'requestId',
            'installationId',
            'status',
            'requestExpiresAt',
            'accessToken',
        ], array_keys($data));
        $this->assertTrue(Str::isUuid($data['requestId']));
        $this->assertTrue(Str::isUuid($data['installationId']));
        $this->assertSame('Pending', $data['status']);
        $this->assertSame(1795263300000, $data['requestExpiresAt']);
        $this->assertNotEmpty($data['accessToken']);
        $this->assertStringNotContainsString('monitorId', $response->getContent());
        $this->assertStringNotContainsString('role', $response->getContent());
        $this->assertDatabaseHas('invitations', [
            'id' => $issued->json('data.id'),
            'secret_hash' => hash('sha256', $secret),
            'consumed_at' => '2026-11-21 12:00:00+00',
        ]);
        $this->assertDatabaseMissing('invitations', ['secret_hash' => $secret]);
        $this->assertDatabaseHas('installations', [
            'id' => $data['installationId'],
            'label' => str_repeat('é', 128),
        ]);
        $this->assertDatabaseHas('pairing_requests', [
            'id' => $data['requestId'],
            'monitor_id' => $host['monitor']->id,
            'invitation_id' => $issued->json('data.id'),
            'installation_id' => $data['installationId'],
            'status' => 'Pending',
            'request_expires_at' => '2026-11-21 12:15:00+00',
            'decided_at' => null,
            'decision_actor_membership_id' => null,
        ]);
        $this->assertSame(0, MonitorMembership::query()
            ->where('installation_id', $data['installationId'])
            ->count());

        $accessToken = PersonalAccessToken::findToken($data['accessToken']);
        $this->assertInstanceOf(PersonalAccessToken::class, $accessToken);
        $this->assertSame($data['installationId'], $accessToken->tokenable_id);
        $this->assertSame(['pairing:pending'], $accessToken->abilities);
        $this->assertSame(1795263300, $accessToken->expires_at->getTimestamp());
        $this->assertNotSame($data['accessToken'], $accessToken->token);
        $this->assertSame(1, PersonalAccessToken::query()
            ->where('tokenable_id', $data['installationId'])
            ->count());
    }

    public function test_redemption_uses_a_full_fifteen_minute_request_ttl_when_the_invitation_is_near_expiry(): void
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
        $this->travelTo('2026-11-21 12:14:59 UTC');

        $response = $fixtures->requestJson(
            'POST',
            '/api/v1/pairing-requests',
            json_encode(['invitationSecret' => $issued->json('data.invitationSecret')], JSON_THROW_ON_ERROR),
            remoteAddress: '198.51.100.32',
        );

        $response->assertCreated();
        $this->assertSame(1795264199000, $response->json('data.requestExpiresAt'));
    }

    public static function invalidRedemptionPayloads(): array
    {
        return [
            'missing secret' => ['{}'],
            'numeric secret' => ['{"invitationSecret":7}'],
            'boolean secret' => ['{"invitationSecret":true}'],
            'null secret' => ['{"invitationSecret":null}'],
            'array secret' => ['{"invitationSecret":[]}'],
            'wrong length' => ['{"invitationSecret":"too-short"}'],
            'invalid secret alphabet' => ['{"invitationSecret":"'.str_repeat('!', 43).'"}'],
            'empty label' => ['{"invitationSecret":"'.str_repeat('A', 43).'","installationLabel":""}'],
            'numeric label' => ['{"invitationSecret":"'.str_repeat('A', 43).'","installationLabel":3}'],
            'null label' => ['{"invitationSecret":"'.str_repeat('A', 43).'","installationLabel":null}'],
            'boolean label' => ['{"invitationSecret":"'.str_repeat('A', 43).'","installationLabel":false}'],
            'array label' => ['{"invitationSecret":"'.str_repeat('A', 43).'","installationLabel":[]}'],
            'overlong UTF-8 label' => [
                json_encode([
                    'invitationSecret' => str_repeat('A', 43),
                    'installationLabel' => str_repeat('é', 129),
                ], JSON_THROW_ON_ERROR),
            ],
            'unknown client authority' => [
                '{"invitationSecret":"'.str_repeat('A', 43).'","monitorId":"'.Str::uuid().'"}',
            ],
            'untrusted installation identifier' => [
                '{"invitationSecret":"'.str_repeat('A', 43).'","installationId":"'.Str::uuid().'"}',
            ],
            'untrusted role' => [
                '{"invitationSecret":"'.str_repeat('A', 43).'","role":"Support"}',
            ],
            'untrusted request identifier' => [
                '{"invitationSecret":"'.str_repeat('A', 43).'","requestId":"'.Str::uuid().'"}',
            ],
            'root array' => ['[]'],
        ];
    }

    #[DataProvider('invalidRedemptionPayloads')]
    public function test_public_redemption_rejects_invalid_or_untrusted_payload_values(string $body): void
    {
        $response = (new AccessAndPairingFixtures($this))->requestJson(
            'POST',
            '/api/v1/pairing-requests',
            $body,
            remoteAddress: '198.51.100.33',
        );

        $response->assertUnprocessable()
            ->assertJsonPath('code', 'invalid_payload')
            ->assertJsonPath('message', 'Os dados enviados são inválidos.');
        $this->assertStringNotContainsString(str_repeat('A', 43), $response->getContent());
        $this->assertStringNotContainsString('monitorId', $response->getContent());
        $this->assertStringNotContainsString('installationId', $response->getContent());
        $this->assertStringNotContainsString('requestId', $response->getContent());
        $this->assertStringNotContainsString('role', $response->getContent());
        $this->assertSame(0, Installation::query()->count());
        $this->assertSame(0, PairingRequest::query()->count());
    }

    public static function unavailableInvitationStates(): array
    {
        return [
            'unknown secret' => ['unknown'],
            'already consumed' => ['consumed'],
            'revoked' => ['revoked'],
            'expired at exact boundary' => ['expired'],
            'expired before request' => ['expired-before'],
            'stale generation' => ['stale'],
            'issuer is no longer current host' => ['issuer-revoked'],
        ];
    }

    #[DataProvider('unavailableInvitationStates')]
    public function test_well_formed_unavailable_invitations_share_one_generic_gone_response(string $state): void
    {
        $this->travelTo('2026-11-21 12:00:00 UTC');
        $fixtures = new AccessAndPairingFixtures($this);
        $host = $fixtures->createHost();
        $secret = rtrim(strtr(base64_encode(str_repeat("\x01", 32)), '+/', '-_'), '=');

        $installationsBeforeRedemption = Installation::query()->count();

        if ($state !== 'unknown') {
            $attributes = [
                'monitor_id' => $host['monitor']->id,
                'issuing_installation_id' => $host['installation']->id,
                'issuing_generation' => 1,
                'secret_hash' => hash('sha256', $secret),
                'expires_at' => now('UTC')->addMinutes(15),
            ];

            if ($state === 'consumed') {
                $attributes['consumed_at'] = now('UTC');
            } elseif ($state === 'revoked') {
                $attributes['revoked_at'] = now('UTC');
            } elseif ($state === 'expired') {
                $attributes['expires_at'] = now('UTC');
            } elseif ($state === 'expired-before') {
                $attributes['expires_at'] = now('UTC')->subSecond();
            } elseif ($state === 'stale') {
                $host['monitor']->update(['host_generation' => 2]);
            } elseif ($state === 'issuer-revoked') {
                $host['membership']->update(['revoked_at' => now('UTC')]);
            }

            Invitation::factory()->create($attributes);
        }

        $response = $fixtures->requestJson(
            'POST',
            '/api/v1/pairing-requests',
            json_encode(['invitationSecret' => $secret], JSON_THROW_ON_ERROR),
            remoteAddress: '198.51.100.34',
        );

        $response->assertGone()->assertExactJson([
            'code' => 'invitation_unavailable',
            'message' => 'Convite indisponível.',
        ]);
        $this->assertSame($installationsBeforeRedemption, Installation::query()->count());
        $this->assertSame(0, PairingRequest::query()->count());
    }

    public function test_pairing_candidate_can_poll_only_its_own_pending_request_without_monitor_metadata(): void
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
        $redeemed = $fixtures->requestJson(
            'POST',
            '/api/v1/pairing-requests',
            json_encode(['invitationSecret' => $issued->json('data.invitationSecret')], JSON_THROW_ON_ERROR),
            remoteAddress: '198.51.100.35',
        );
        $redeemed->assertCreated();
        $id = $redeemed->json('data.requestId');

        $response = $fixtures->requestJson(
            'GET',
            '/api/v1/pairing-requests/current?requestId='.Str::uuid().'&installationId='.Str::uuid(),
            headers: ['Authorization' => 'Bearer '.$redeemed->json('data.accessToken')],
            remoteAddress: '198.51.100.35',
        );

        $response->assertOk()->assertExactJson([
            'data' => [
                'id' => $id,
                'status' => 'Pending',
                'requestExpiresAt' => 1795263300000,
                'decidedAt' => null,
                'monitor' => null,
            ],
        ]);
        $this->assertStringNotContainsString($host['monitor']->id, $response->getContent());
        $this->assertStringNotContainsString($redeemed->json('data.accessToken'), $response->getContent());
    }

    public function test_candidate_polling_returns_only_current_approved_support_metadata_after_the_request_deadline(): void
    {
        $this->travelTo('2026-11-21 12:00:00 UTC');
        $fixtures = new AccessAndPairingFixtures($this);
        $host = $fixtures->createHost();
        $candidate = Installation::factory()->create();
        $supportMembership = MonitorMembership::factory()
            ->for($host['monitor'])
            ->for($candidate)
            ->create([
                'role' => AccessRole::Support,
                'generation' => null,
            ]);
        $invitation = Invitation::factory()->create([
            'monitor_id' => $host['monitor']->id,
            'issuing_installation_id' => $host['installation']->id,
            'issuing_generation' => 1,
            'consumed_at' => now('UTC')->subMinutes(16),
            'expires_at' => now('UTC')->subMinutes(1),
        ]);
        $pairingRequest = PairingRequest::factory()->create([
            'monitor_id' => $host['monitor']->id,
            'invitation_id' => $invitation->id,
            'installation_id' => $candidate->id,
            'status' => PairingRequestStatus::Approved,
            'request_expires_at' => now('UTC')->subMinute(),
            'decided_at' => now('UTC')->subMinutes(16),
            'decision_actor_membership_id' => $host['membership']->id,
        ]);
        $pendingToken = $candidate->createToken('approved-support', ['support:monitor']);

        $response = $fixtures->requestJson(
            'GET',
            '/api/v1/pairing-requests/current',
            headers: ['Authorization' => 'Bearer '.$pendingToken->plainTextToken],
            remoteAddress: '198.51.100.36',
        );

        $response->assertOk()->assertExactJson([
            'data' => [
                'id' => $pairingRequest->id,
                'status' => 'Approved',
                'requestExpiresAt' => $pairingRequest->request_expires_at->getTimestamp() * 1000,
                'decidedAt' => $pairingRequest->decided_at->getTimestamp() * 1000,
                'monitor' => [
                    'id' => $host['monitor']->id,
                    'membershipId' => $supportMembership->id,
                    'role' => 'Support',
                ],
            ],
        ]);
    }

    public function test_redeeming_the_same_secret_after_a_successful_response_loss_does_not_create_another_request(): void
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
        ], JSON_THROW_ON_ERROR);
        $firstResponse = $fixtures->requestJson(
            'POST',
            '/api/v1/pairing-requests',
            $body,
            remoteAddress: '198.51.100.37',
        );
        $firstResponse->assertCreated();
        $installationsAfterFirstRedemption = Installation::query()->count();

        $retryResponse = $fixtures->requestJson(
            'POST',
            '/api/v1/pairing-requests',
            $body,
            remoteAddress: '198.51.100.37',
        );

        $retryResponse->assertGone()->assertExactJson([
            'code' => 'invitation_unavailable',
            'message' => 'Convite indisponível.',
        ]);
        $this->assertSame($installationsAfterFirstRedemption, Installation::query()->count());
        $this->assertSame(1, PairingRequest::query()->count());
        $this->assertSame(1, PersonalAccessToken::query()
            ->where('tokenable_id', $firstResponse->json('data.installationId'))
            ->count());
    }

    public function test_empty_redemption_body_and_non_json_content_type_use_the_existing_api_problem_contract(): void
    {
        $fixtures = new AccessAndPairingFixtures($this);
        $emptyBody = $fixtures->requestJson(
            'POST',
            '/api/v1/pairing-requests',
            '',
            remoteAddress: '198.51.100.38',
        );
        $emptyBody->assertUnprocessable()->assertJsonPath('code', 'invalid_payload');

        $unsupportedMediaType = $this->call(
            'POST',
            '/api/v1/pairing-requests',
            [],
            [],
            [],
            ['CONTENT_TYPE' => 'text/plain', 'REMOTE_ADDR' => '198.51.100.39'],
            '{}',
        );
        $unsupportedMediaType->assertUnsupportedMediaType()
            ->assertJsonPath('code', 'unsupported_media_type');
    }

    public function test_pairing_candidate_without_its_own_request_gets_not_found(): void
    {
        $candidate = Installation::factory()->create();
        $token = $candidate->createToken('no-pairing-request', ['pairing:pending'])->plainTextToken;

        $response = (new AccessAndPairingFixtures($this))->requestJson(
            'GET',
            '/api/v1/pairing-requests/current',
            headers: ['Authorization' => 'Bearer '.$token],
        );

        $response->assertNotFound()->assertJsonPath('code', 'resource_not_found');
    }

    public function test_pending_candidate_token_is_unauthenticated_at_its_exact_expiry(): void
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
        $redeemed = $fixtures->requestJson(
            'POST',
            '/api/v1/pairing-requests',
            json_encode(['invitationSecret' => $issued->json('data.invitationSecret')], JSON_THROW_ON_ERROR),
            remoteAddress: '198.51.100.40',
        );
        $redeemed->assertCreated();
        $this->travelTo('2026-11-21 12:15:00 UTC');

        $response = $fixtures->requestJson(
            'GET',
            '/api/v1/pairing-requests/current',
            headers: ['Authorization' => 'Bearer '.$redeemed->json('data.accessToken')],
            remoteAddress: '198.51.100.40',
        );

        $response->assertUnauthorized()->assertJsonPath('code', 'unauthenticated');
    }

    public function test_elapsed_pending_request_with_nonexpiring_corrupt_token_is_reported_unavailable_without_mutation(): void
    {
        $this->travelTo('2026-11-21 12:00:00 UTC');
        $host = (new AccessAndPairingFixtures($this))->createHost();
        $candidate = Installation::factory()->create();
        $invitation = Invitation::factory()->create([
            'monitor_id' => $host['monitor']->id,
            'issuing_installation_id' => $host['installation']->id,
            'issuing_generation' => 1,
            'consumed_at' => now('UTC')->subMinutes(20),
        ]);
        $pairingRequest = PairingRequest::factory()->pending()->create([
            'monitor_id' => $host['monitor']->id,
            'invitation_id' => $invitation->id,
            'installation_id' => $candidate->id,
            'request_expires_at' => now('UTC')->subSecond(),
        ]);
        $token = $candidate->createToken('corrupt-pending-token', ['pairing:pending']);

        $response = (new AccessAndPairingFixtures($this))->requestJson(
            'GET',
            '/api/v1/pairing-requests/current',
            headers: ['Authorization' => 'Bearer '.$token->plainTextToken],
        );

        $response->assertGone()->assertJsonPath('code', 'pairing_request_unavailable');
        $this->assertSame(PairingRequestStatus::Pending, $pairingRequest->fresh()->status);
        $this->assertNull($pairingRequest->fresh()->decided_at);
    }

    public function test_revoked_support_membership_cannot_expose_an_approved_monitor_candidate(): void
    {
        $host = (new AccessAndPairingFixtures($this))->createHost();
        $candidate = Installation::factory()->create();
        $membership = MonitorMembership::factory()
            ->for($host['monitor'])
            ->for($candidate)
            ->create([
                'role' => AccessRole::Support,
                'generation' => null,
                'revoked_at' => now(),
            ]);
        $invitation = Invitation::factory()->create([
            'monitor_id' => $host['monitor']->id,
            'issuing_installation_id' => $host['installation']->id,
            'issuing_generation' => 1,
            'consumed_at' => now(),
        ]);
        PairingRequest::factory()->create([
            'monitor_id' => $host['monitor']->id,
            'invitation_id' => $invitation->id,
            'installation_id' => $candidate->id,
            'status' => PairingRequestStatus::Approved,
            'decision_actor_membership_id' => $host['membership']->id,
            'decided_at' => now(),
        ]);
        $token = $candidate->createToken('revoked-support-token', ['support:monitor']);

        $response = (new AccessAndPairingFixtures($this))->requestJson(
            'GET',
            '/api/v1/pairing-requests/current',
            headers: ['Authorization' => 'Bearer '.$token->plainTextToken],
        );

        $response->assertGone()->assertJsonPath('code', 'pairing_request_unavailable');
        $this->assertStringNotContainsString($host['monitor']->id, $response->getContent());
        $this->assertNotNull($membership->fresh()->revoked_at);
    }
}
