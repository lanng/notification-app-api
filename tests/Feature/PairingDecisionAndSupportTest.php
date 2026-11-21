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
use Tests\Support\FakeOwnerIdentityVerifier;
use Tests\TestCase;

class PairingDecisionAndSupportTest extends TestCase
{
    use LazilyRefreshDatabase;

    public function test_current_host_lists_no_support_memberships_for_a_monitor_without_support(): void
    {
        $fixtures = new AccessAndPairingFixtures($this);
        $host = $fixtures->createHost();

        $response = $fixtures->requestJson(
            'GET',
            "/api/v1/monitors/{$host['monitor']->id}/supports",
            headers: ['Authorization' => 'Bearer '.$host['token']],
        );

        $response->assertOk()->assertExactJson(['data' => []]);
    }

    public function test_support_listing_is_ordered_redacted_and_capped_at_three_active_memberships(): void
    {
        $this->travelTo('2026-11-21 12:00:00 UTC');
        $fixtures = new AccessAndPairingFixtures($this);
        $host = $fixtures->createHost();
        $youngestSupport = $fixtures->createSupportInstallation($host['monitor']);
        $youngestSupport['installation']->update(['label' => 'Support device A']);
        $youngestSupport['membership']->forceFill([
            'id' => '00000000-0000-4000-8000-000000000003',
            'approved_at' => '2026-11-21 12:00:00 UTC',
        ])->save();
        $oldestSupport = $fixtures->createSupportInstallation($host['monitor']);
        $oldestSupport['installation']->update(['label' => 'Support device B']);
        $oldestSupport['membership']->forceFill([
            'id' => '00000000-0000-4000-8000-000000000004',
            'approved_at' => '2026-11-21 11:58:00 UTC',
        ])->save();
        $middleSupportC = $fixtures->createSupportInstallation($host['monitor']);
        $middleSupportC['installation']->update(['label' => 'Support device C']);
        $middleSupportC['membership']->forceFill([
            'id' => '00000000-0000-4000-8000-000000000002',
            'approved_at' => '2026-11-21 11:59:00 UTC',
        ])->save();
        $middleSupportD = $fixtures->createSupportInstallation($host['monitor']);
        $middleSupportD['installation']->update(['label' => 'Support device D']);
        $middleSupportD['membership']->forceFill([
            'id' => '00000000-0000-4000-8000-000000000001',
            'approved_at' => '2026-11-21 11:59:00 UTC',
        ])->save();

        $revokedSupport = $fixtures->createSupportInstallation($host['monitor']);
        $revokedSupport['membership']->update([
            'revoked_at' => now('UTC')->startOfSecond(),
        ]);

        $response = $fixtures->requestJson(
            'GET',
            "/api/v1/monitors/{$host['monitor']->id}/supports",
            headers: ['Authorization' => 'Bearer '.$host['token']],
        );

        $response->assertOk()->assertExactJson([
            'data' => [
                [
                    'membershipId' => '00000000-0000-4000-8000-000000000004',
                    'installationId' => $oldestSupport['installation']->id,
                    'label' => 'Support device B',
                    'role' => 'Support',
                    'status' => 'Active',
                    'approvedAt' => 1795262280000,
                ],
                [
                    'membershipId' => '00000000-0000-4000-8000-000000000001',
                    'installationId' => $middleSupportD['installation']->id,
                    'label' => 'Support device D',
                    'role' => 'Support',
                    'status' => 'Active',
                    'approvedAt' => 1795262340000,
                ],
                [
                    'membershipId' => '00000000-0000-4000-8000-000000000002',
                    'installationId' => $middleSupportC['installation']->id,
                    'label' => 'Support device C',
                    'role' => 'Support',
                    'status' => 'Active',
                    'approvedAt' => 1795262340000,
                ],
            ],
        ]);
        $this->assertStringNotContainsString($host['installation']->id, $response->getContent());
        $this->assertStringNotContainsString($revokedSupport['installation']->id, $response->getContent());
        $this->assertStringNotContainsString('accessToken', $response->getContent());
    }

    public function test_current_host_lists_only_pending_pairing_requests_with_redacted_candidate_data(): void
    {
        $this->travelTo('2026-11-21 12:00:00 UTC');
        $fixtures = new AccessAndPairingFixtures($this);
        $host = $fixtures->createHost();
        $invitation = $fixtures->requestJson(
            'POST',
            "/api/v1/monitors/{$host['monitor']->id}/invitations",
            '{}',
            ['Authorization' => 'Bearer '.$host['token']],
        );
        $redeemed = $fixtures->requestJson(
            'POST',
            '/api/v1/pairing-requests',
            json_encode([
                'invitationSecret' => $invitation->json('data.invitationSecret'),
                'installationLabel' => 'Candidate label',
            ], JSON_THROW_ON_ERROR),
            remoteAddress: '198.51.100.50',
        );
        $redeemed->assertCreated();

        $response = $fixtures->requestJson(
            'GET',
            "/api/v1/monitors/{$host['monitor']->id}/pairing-requests",
            headers: ['Authorization' => 'Bearer '.$host['token']],
        );

        $response->assertOk()->assertExactJson([
            'data' => [[
                'id' => $redeemed->json('data.requestId'),
                'status' => 'Pending',
                'installation' => [
                    'id' => $redeemed->json('data.installationId'),
                    'label' => 'Candidate label',
                ],
                'createdAt' => 1795262400000,
                'requestExpiresAt' => 1795263300000,
            ]],
        ]);
        $this->assertStringNotContainsString($redeemed->json('data.accessToken'), $response->getContent());
    }

    public function test_pairing_request_listing_is_current_pending_only_ordered_and_capped_at_fifty(): void
    {
        $this->travelTo('2026-11-21 12:00:00 UTC');
        $fixtures = new AccessAndPairingFixtures($this);
        $host = $fixtures->createHost();
        $pendingRequests = [];

        for ($index = 0; $index < 51; $index++) {
            $pendingRequests[] = $this->createPairingRequestFixture(
                $host['monitor'],
                PairingRequestStatus::Pending,
                1,
                now('UTC')->addMinutes(15),
                now('UTC')->addSeconds(intdiv($index, 2)),
                'Candidate '.$index,
            );
        }

        $this->createPairingRequestFixture(
            $host['monitor'],
            PairingRequestStatus::Pending,
            1,
            now('UTC'),
            now('UTC')->addSeconds(100),
            'Expired candidate',
        );
        $this->createPairingRequestFixture(
            $host['monitor'],
            PairingRequestStatus::Approved,
            1,
            now('UTC')->addMinutes(15),
            now('UTC')->addSeconds(101),
            'Approved candidate',
        );
        $this->createPairingRequestFixture(
            $host['monitor'],
            PairingRequestStatus::Rejected,
            1,
            now('UTC')->addMinutes(15),
            now('UTC')->addSeconds(102),
            'Rejected candidate',
        );
        $this->createPairingRequestFixture(
            $host['monitor'],
            PairingRequestStatus::Cancelled,
            1,
            now('UTC')->addMinutes(15),
            now('UTC')->addSeconds(103),
            'Cancelled candidate',
        );
        $this->createPairingRequestFixture(
            $host['monitor'],
            PairingRequestStatus::Pending,
            0,
            now('UTC')->addMinutes(15),
            now('UTC')->addSeconds(104),
            'Stale candidate',
        );
        $expectedIds = collect($pendingRequests)
            ->sort(function (PairingRequest $left, PairingRequest $right): int {
                $createdAtOrder = $left->created_at->getTimestamp() <=> $right->created_at->getTimestamp();

                return $createdAtOrder === 0
                    ? strcmp($left->id, $right->id)
                    : $createdAtOrder;
            })
            ->take(50)
            ->pluck('id')
            ->all();

        $response = $fixtures->requestJson(
            'GET',
            "/api/v1/monitors/{$host['monitor']->id}/pairing-requests",
            headers: ['Authorization' => 'Bearer '.$host['token']],
        );

        $response->assertOk();
        $listed = $response->json('data');
        $this->assertCount(50, $listed);
        $this->assertSame($expectedIds, array_column($listed, 'id'));
        $this->assertSame([
            'id',
            'status',
            'installation',
            'createdAt',
            'requestExpiresAt',
        ], array_keys($listed[0]));
        $this->assertSame(['id', 'label'], array_keys($listed[0]['installation']));
        $this->assertStringNotContainsString('secret_hash', $response->getContent());
        $this->assertStringNotContainsString('accessToken', $response->getContent());
    }

    public function test_support_with_wildcard_abilities_is_forbidden_before_malformed_resource_ids(): void
    {
        $fixtures = new AccessAndPairingFixtures($this);
        $host = $fixtures->createHost();
        $support = $fixtures->createSupportInstallation($host['monitor']);
        $wildcardToken = $support['installation']->createToken('wildcard-support', ['*'])->plainTextToken;
        $headers = ['Authorization' => 'Bearer '.$wildcardToken];

        $requestListing = $fixtures->requestJson(
            'GET',
            '/api/v1/monitors/not-a-uuid/pairing-requests',
            headers: $headers,
        );
        $requestListing->assertForbidden()->assertJsonPath('code', 'access_forbidden');
        $approval = $fixtures->requestJson(
            'POST',
            '/api/v1/monitors/not-a-uuid/pairing-requests/not-a-uuid/approval',
            '{}',
            $headers,
        );
        $approval->assertForbidden()->assertJsonPath('code', 'access_forbidden');
        $revocation = $fixtures->requestJson(
            'DELETE',
            '/api/v1/monitors/not-a-uuid/supports/not-a-uuid',
            '{}',
            $headers,
        );
        $revocation->assertForbidden()->assertJsonPath('code', 'access_forbidden');
    }

    public function test_host_receives_generic_not_found_for_foreign_monitors_and_pairing_requests(): void
    {
        $fixtures = new AccessAndPairingFixtures($this);
        $host = $fixtures->createHost();
        $foreignMonitor = Monitor::factory()->create();
        $foreignSupport = $fixtures->createSupportInstallation($foreignMonitor);
        $foreignRequest = $this->createPairingRequestFixture(
            $foreignMonitor,
            PairingRequestStatus::Pending,
            1,
            now('UTC')->addMinutes(15),
            now('UTC'),
            'Foreign candidate',
        );
        $headers = ['Authorization' => 'Bearer '.$host['token']];

        $foreignMonitorResponse = $fixtures->requestJson(
            'POST',
            "/api/v1/monitors/{$foreignMonitor->id}/pairing-requests/not-a-uuid/approval",
            '{}',
            $headers,
        );
        $missingMonitorResponse = $fixtures->requestJson(
            'POST',
            '/api/v1/monitors/'.Str::uuid().'/pairing-requests/not-a-uuid/approval',
            '{}',
            $headers,
        );
        $expectedNotFound = [
            'code' => 'resource_not_found',
            'message' => 'Recurso não encontrado.',
        ];
        $foreignMonitorResponse->assertNotFound()->assertExactJson($expectedNotFound);
        $missingMonitorResponse->assertNotFound()->assertExactJson($expectedNotFound);
        $ownMalformedRequest = $fixtures->requestJson(
            'POST',
            "/api/v1/monitors/{$host['monitor']->id}/pairing-requests/not-a-uuid/approval",
            '{}',
            $headers,
        );
        $ownMissingRequest = $fixtures->requestJson(
            'POST',
            "/api/v1/monitors/{$host['monitor']->id}/pairing-requests/".Str::uuid().'/approval',
            '{}',
            $headers,
        );
        $ownForeignRequest = $fixtures->requestJson(
            'POST',
            "/api/v1/monitors/{$host['monitor']->id}/pairing-requests/{$foreignRequest->id}/approval",
            '{}',
            $headers,
        );
        $foreignMembershipResponse = $fixtures->requestJson(
            'DELETE',
            "/api/v1/monitors/{$host['monitor']->id}/supports/{$foreignSupport['membership']->id}",
            '{}',
            $headers,
        );
        $missingMembershipResponse = $fixtures->requestJson(
            'DELETE',
            "/api/v1/monitors/{$host['monitor']->id}/supports/".Str::uuid(),
            '{}',
            $headers,
        );

        $ownMalformedRequest->assertNotFound()->assertExactJson($expectedNotFound);
        $ownMissingRequest->assertNotFound()->assertExactJson($expectedNotFound);
        $ownForeignRequest->assertNotFound()->assertExactJson($expectedNotFound);
        $foreignMembershipResponse->assertNotFound()->assertExactJson($expectedNotFound);
        $missingMembershipResponse->assertNotFound()->assertExactJson($expectedNotFound);
        $this->assertNull($foreignSupport['membership']->fresh()->revoked_at);
    }

    public function test_host_cannot_revoke_its_own_host_membership_through_the_support_route(): void
    {
        $fixtures = new AccessAndPairingFixtures($this);
        $host = $fixtures->createHost();

        $response = $fixtures->requestJson(
            'DELETE',
            "/api/v1/monitors/{$host['monitor']->id}/supports/{$host['membership']->id}",
            '{}',
            ['Authorization' => 'Bearer '.$host['token']],
        );

        $response->assertNotFound()->assertJsonPath('code', 'resource_not_found');
        $this->assertNull($host['membership']->fresh()->revoked_at);
        $this->assertDatabaseHas('personal_access_tokens', [
            'id' => $host['accessToken']->id,
        ]);
        $this->assertSame('Host', $host['membership']->fresh()->role->value);
    }

    public function test_old_host_token_is_unauthenticated_on_pairing_routes_after_a_real_host_swap(): void
    {
        $this->travelTo('2026-11-21 12:00:00 UTC');
        $fixtures = new AccessAndPairingFixtures($this);
        $host = $fixtures->createHost();
        $candidate = $this->createPendingPairingRequest(
            $fixtures,
            $host,
            '198.51.100.74',
        );
        $this->travelTo('2026-11-21 12:01:00 UTC');

        $swap = $fixtures->requestJson(
            'POST',
            '/api/v1/owner/host-activations',
            '{"confirmation":true,"expectedGeneration":"1"}',
            ['Authorization' => 'Bearer '.FakeOwnerIdentityVerifier::TEST_BEARER_TOKEN],
            '192.0.2.11',
        );
        $swap->assertOk();

        $response = $fixtures->requestJson(
            'GET',
            "/api/v1/monitors/{$host['monitor']->id}/pairing-requests",
            headers: ['Authorization' => 'Bearer '.$host['token']],
        );

        $response->assertUnauthorized()->assertJsonPath('code', 'unauthenticated');
        $this->assertDatabaseMissing('personal_access_tokens', [
            'id' => $host['accessToken']->id,
        ]);
        $cancelledRequest = PairingRequest::query()->findOrFail($candidate['requestId']);
        $this->assertSame(PairingRequestStatus::Cancelled, $cancelledRequest->status);
        $this->assertNull($cancelledRequest->decision_actor_membership_id);
        $this->assertDatabaseMissing('personal_access_tokens', [
            'tokenable_id' => $candidate['installationId'],
        ]);
        $newHostToken = $swap->json('data.accessToken');

        foreach (['approval', 'rejection'] as $decision) {
            $terminalDecision = $fixtures->requestJson(
                'POST',
                "/api/v1/monitors/{$host['monitor']->id}/pairing-requests/{$candidate['requestId']}/{$decision}",
                '{}',
                ['Authorization' => 'Bearer '.$newHostToken],
            );
            $terminalDecision->assertConflict()->assertJsonPath('code', 'pairing_request_terminal');
        }

        $this->assertSame(0, MonitorMembership::query()
            ->where('installation_id', $candidate['installationId'])
            ->count());
    }

    public function test_approval_rejects_client_supplied_authority_fields_without_state_changes(): void
    {
        $this->travelTo('2026-11-21 12:00:00 UTC');
        $fixtures = new AccessAndPairingFixtures($this);
        $host = $fixtures->createHost();
        $candidate = $this->createPendingPairingRequest(
            $fixtures,
            $host,
            '198.51.100.72',
        );
        $candidateToken = PersonalAccessToken::findToken($candidate['token']);
        $this->assertInstanceOf(PersonalAccessToken::class, $candidateToken);
        $candidateTokenExpiry = $candidateToken->expires_at->getTimestamp();

        $response = $fixtures->requestJson(
            'POST',
            "/api/v1/monitors/{$host['monitor']->id}/pairing-requests/{$candidate['requestId']}/approval",
            '{"role":"Host"}',
            ['Authorization' => 'Bearer '.$host['token']],
        );

        $response->assertUnprocessable()->assertJsonPath('code', 'invalid_payload');
        $this->assertSame(PairingRequestStatus::Pending, PairingRequest::query()
            ->findOrFail($candidate['requestId'])->status);
        $this->assertNull(PairingRequest::query()
            ->findOrFail($candidate['requestId'])->decided_at);
        $this->assertSame(0, MonitorMembership::query()
            ->where('installation_id', $candidate['installationId'])
            ->count());
        $this->assertSame($candidateTokenExpiry, PersonalAccessToken::query()
            ->findOrFail($candidateToken->id)->expires_at->getTimestamp());
    }

    public function test_approval_does_not_create_support_access_when_the_pending_token_is_missing(): void
    {
        $this->travelTo('2026-11-21 12:00:00 UTC');
        $fixtures = new AccessAndPairingFixtures($this);
        $host = $fixtures->createHost();
        $candidate = $this->createPendingPairingRequest(
            $fixtures,
            $host,
            '198.51.100.73',
        );
        PersonalAccessToken::query()
            ->where('tokenable_id', $candidate['installationId'])
            ->delete();

        $response = $fixtures->requestJson(
            'POST',
            "/api/v1/monitors/{$host['monitor']->id}/pairing-requests/{$candidate['requestId']}/approval",
            '{}',
            ['Authorization' => 'Bearer '.$host['token']],
        );

        $response->assertGone()->assertJsonPath('code', 'pairing_request_unavailable');
        $this->assertSame(PairingRequestStatus::Pending, PairingRequest::query()
            ->findOrFail($candidate['requestId'])->status);
        $this->assertNull(PairingRequest::query()
            ->findOrFail($candidate['requestId'])->decided_at);
        $this->assertSame(0, MonitorMembership::query()
            ->where('installation_id', $candidate['installationId'])
            ->count());
        $this->assertDatabaseMissing('personal_access_tokens', [
            'tokenable_id' => $candidate['installationId'],
        ]);
    }

    public function test_host_approval_preserves_the_candidate_token_and_returns_only_sanitized_support_data(): void
    {
        $this->travelTo('2026-11-21 12:00:00 UTC');
        $fixtures = new AccessAndPairingFixtures($this);
        $host = $fixtures->createHost();
        $invitation = $fixtures->requestJson(
            'POST',
            "/api/v1/monitors/{$host['monitor']->id}/invitations",
            '{}',
            ['Authorization' => 'Bearer '.$host['token']],
        );
        $this->travelTo('2026-11-21 12:14:59 UTC');
        $redeemed = $fixtures->requestJson(
            'POST',
            '/api/v1/pairing-requests',
            json_encode(['invitationSecret' => $invitation->json('data.invitationSecret')], JSON_THROW_ON_ERROR),
            remoteAddress: '198.51.100.51',
        );
        $candidateToken = PersonalAccessToken::findToken($redeemed->json('data.accessToken'));
        $this->assertInstanceOf(PersonalAccessToken::class, $candidateToken);
        $candidateTokenId = $candidateToken->id;
        $candidateTokenHash = $candidateToken->token;
        $pairingRequestId = $redeemed->json('data.requestId');
        $this->assertSame(1795264199000, $redeemed->json('data.requestExpiresAt'));
        $this->travelTo('2026-11-21 12:15:00 UTC');

        $response = $fixtures->requestJson(
            'POST',
            "/api/v1/monitors/{$host['monitor']->id}/pairing-requests/{$pairingRequestId}/approval",
            '{}',
            ['Authorization' => 'Bearer '.$host['token']],
        );

        $response->assertOk();
        $membership = MonitorMembership::query()
            ->where('monitor_id', $host['monitor']->id)
            ->where('installation_id', $redeemed->json('data.installationId'))
            ->firstOrFail();
        $this->assertSame(AccessRole::Support, $membership->role);
        $this->assertNull($membership->generation);
        $this->assertNull($membership->revoked_at);
        $this->assertSame(1795263300000, $membership->approved_at->getTimestamp() * 1000);
        $response->assertExactJson([
            'data' => [
                'requestId' => $pairingRequestId,
                'status' => 'Approved',
                'membershipId' => $membership->id,
                'role' => 'Support',
                'decidedAt' => 1795263300000,
            ],
        ]);
        $this->assertStringNotContainsString($redeemed->json('data.accessToken'), $response->getContent());
        $this->assertSame(PairingRequestStatus::Approved, PairingRequest::query()
            ->findOrFail($pairingRequestId)->status);
        $this->assertSame($host['membership']->id, PairingRequest::query()
            ->findOrFail($pairingRequestId)->decision_actor_membership_id);
        $rejection = $fixtures->requestJson(
            'POST',
            "/api/v1/monitors/{$host['monitor']->id}/pairing-requests/{$pairingRequestId}/rejection",
            '{}',
            ['Authorization' => 'Bearer '.$host['token']],
        );
        $rejection->assertConflict()->assertJsonPath('code', 'pairing_request_terminal');
        $this->assertDatabaseHas('personal_access_tokens', ['id' => $candidateTokenId]);

        $candidateToken->refresh();
        $this->assertSame($candidateTokenId, $candidateToken->id);
        $this->assertSame($candidateTokenHash, $candidateToken->token);
        $this->assertSame(['pairing:pending'], $candidateToken->abilities);
        $this->assertNull($candidateToken->expires_at);
        $this->assertSame(1, PersonalAccessToken::query()
            ->where('tokenable_id', $redeemed->json('data.installationId'))
            ->count());
        $this->travelTo('2026-11-21 12:30:00 UTC');

        $poll = $fixtures->requestJson(
            'GET',
            '/api/v1/pairing-requests/current',
            headers: ['Authorization' => 'Bearer '.$redeemed->json('data.accessToken')],
            remoteAddress: '198.51.100.51',
        );

        $poll->assertOk()->assertExactJson([
            'data' => [
                'id' => $pairingRequestId,
                'status' => 'Approved',
                'requestExpiresAt' => 1795264199000,
                'decidedAt' => 1795263300000,
                'monitor' => [
                    'id' => $host['monitor']->id,
                    'membershipId' => $membership->id,
                    'role' => 'Support',
                ],
            ],
        ]);
    }

    public function test_host_rejection_is_idempotent_after_deadline_and_revokes_the_candidate_credential(): void
    {
        $this->travelTo('2026-11-21 12:00:00 UTC');
        $fixtures = new AccessAndPairingFixtures($this);
        $host = $fixtures->createHost();
        $invitation = $fixtures->requestJson(
            'POST',
            "/api/v1/monitors/{$host['monitor']->id}/invitations",
            '{}',
            ['Authorization' => 'Bearer '.$host['token']],
        );
        $redeemed = $fixtures->requestJson(
            'POST',
            '/api/v1/pairing-requests',
            json_encode(['invitationSecret' => $invitation->json('data.invitationSecret')], JSON_THROW_ON_ERROR),
            remoteAddress: '198.51.100.52',
        );
        $pairingRequestId = $redeemed->json('data.requestId');
        $installationId = $redeemed->json('data.installationId');
        $extraCandidateToken = Installation::query()
            ->findOrFail($installationId)
            ->createToken('extra-candidate-credential', ['extra:ability']);
        $this->travelTo('2026-11-21 12:02:00 UTC');

        $response = $fixtures->requestJson(
            'POST',
            "/api/v1/monitors/{$host['monitor']->id}/pairing-requests/{$pairingRequestId}/rejection",
            '{}',
            ['Authorization' => 'Bearer '.$host['token']],
        );

        $expected = [
            'data' => [
                'requestId' => $pairingRequestId,
                'status' => 'Rejected',
                'decidedAt' => 1795262520000,
            ],
        ];
        $response->assertOk()->assertExactJson($expected);
        $pairingRequest = PairingRequest::query()->findOrFail($pairingRequestId);
        $this->assertSame(PairingRequestStatus::Rejected, $pairingRequest->status);
        $this->assertSame($host['membership']->id, $pairingRequest->decision_actor_membership_id);
        $this->assertSame(0, MonitorMembership::query()
            ->where('installation_id', $installationId)
            ->count());
        $this->assertDatabaseMissing('personal_access_tokens', [
            'tokenable_id' => $installationId,
        ]);
        $this->assertDatabaseMissing('personal_access_tokens', [
            'id' => $extraCandidateToken->accessToken->id,
        ]);
        $this->travelTo('2026-11-21 12:20:00 UTC');

        $retry = $fixtures->requestJson(
            'POST',
            "/api/v1/monitors/{$host['monitor']->id}/pairing-requests/{$pairingRequestId}/rejection",
            '{}',
            ['Authorization' => 'Bearer '.$host['token']],
        );
        $retry->assertOk()->assertExactJson($expected);

        $approval = $fixtures->requestJson(
            'POST',
            "/api/v1/monitors/{$host['monitor']->id}/pairing-requests/{$pairingRequestId}/approval",
            '{}',
            ['Authorization' => 'Bearer '.$host['token']],
        );
        $approval->assertConflict()->assertJsonPath('code', 'pairing_request_terminal');
        $poll = $fixtures->requestJson(
            'GET',
            '/api/v1/pairing-requests/current',
            headers: ['Authorization' => 'Bearer '.$redeemed->json('data.accessToken')],
            remoteAddress: '198.51.100.52',
        );
        $poll->assertUnauthorized()->assertJsonPath('code', 'unauthenticated');
    }

    public function test_support_capacity_is_three_and_revocation_frees_one_slot_for_approval(): void
    {
        $this->travelTo('2026-11-21 12:00:00 UTC');
        $fixtures = new AccessAndPairingFixtures($this);
        $host = $fixtures->createHost();
        $pending = [];

        for ($index = 0; $index < 4; $index++) {
            $pending[] = $this->createPendingPairingRequest(
                $fixtures,
                $host,
                '198.51.100.'.(60 + $index),
            );
        }

        foreach (array_slice($pending, 0, 3) as $candidate) {
            $approval = $fixtures->requestJson(
                'POST',
                "/api/v1/monitors/{$host['monitor']->id}/pairing-requests/{$candidate['requestId']}/approval",
                '{}',
                ['Authorization' => 'Bearer '.$host['token']],
            );
            $approval->assertOk();
        }

        $this->assertSame(3, MonitorMembership::query()
            ->where('monitor_id', $host['monitor']->id)
            ->where('role', AccessRole::Support->value)
            ->whereNull('revoked_at')
            ->count());
        $fourthCandidate = $pending[3];
        $fourthToken = PersonalAccessToken::findToken($fourthCandidate['token']);
        $this->assertInstanceOf(PersonalAccessToken::class, $fourthToken);
        $fourthTokenExpiry = $fourthToken->expires_at->getTimestamp();

        $fullResponse = $fixtures->requestJson(
            'POST',
            "/api/v1/monitors/{$host['monitor']->id}/pairing-requests/{$fourthCandidate['requestId']}/approval",
            '{}',
            ['Authorization' => 'Bearer '.$host['token']],
        );

        $fullResponse->assertConflict()->assertJsonPath('code', 'support_limit_reached');
        $this->assertSame(PairingRequestStatus::Pending, PairingRequest::query()
            ->findOrFail($fourthCandidate['requestId'])->status);
        $this->assertNull(PairingRequest::query()
            ->findOrFail($fourthCandidate['requestId'])->decided_at);
        $this->assertSame($fourthTokenExpiry, PersonalAccessToken::query()
            ->findOrFail($fourthToken->id)->expires_at->getTimestamp());
        $this->assertSame(0, MonitorMembership::query()
            ->where('installation_id', $fourthCandidate['installationId'])
            ->count());

        $firstSupport = MonitorMembership::query()
            ->where('monitor_id', $host['monitor']->id)
            ->where('installation_id', $pending[0]['installationId'])
            ->firstOrFail();
        $revoke = $fixtures->requestJson(
            'DELETE',
            "/api/v1/monitors/{$host['monitor']->id}/supports/{$firstSupport->id}",
            '{}',
            ['Authorization' => 'Bearer '.$host['token']],
        );
        $revoke->assertNoContent();

        $approvalAfterRevocation = $fixtures->requestJson(
            'POST',
            "/api/v1/monitors/{$host['monitor']->id}/pairing-requests/{$fourthCandidate['requestId']}/approval",
            '{}',
            ['Authorization' => 'Bearer '.$host['token']],
        );

        $approvalAfterRevocation->assertOk();
        $this->assertNotNull($firstSupport->fresh()->revoked_at);
        $this->assertSame(3, MonitorMembership::query()
            ->where('monitor_id', $host['monitor']->id)
            ->where('role', AccessRole::Support->value)
            ->whereNull('revoked_at')
            ->count());
    }

    public function test_same_label_never_replaces_support_and_old_access_is_revoked_only_by_the_host(): void
    {
        $this->travelTo('2026-11-21 12:00:00 UTC');
        $fixtures = new AccessAndPairingFixtures($this);
        $host = $fixtures->createHost();
        $oldSupport = $fixtures->createSupportInstallation($host['monitor']);
        $oldSupport['installation']->update(['label' => 'Shared watch']);
        $fixtures->createSupportInstallation($host['monitor']);
        $fixtures->createSupportInstallation($host['monitor']);
        $candidate = $this->createPendingPairingRequest(
            $fixtures,
            $host,
            '198.51.100.75',
            'Shared watch',
        );

        $deniedApproval = $fixtures->requestJson(
            'POST',
            "/api/v1/monitors/{$host['monitor']->id}/pairing-requests/{$candidate['requestId']}/approval",
            '{}',
            ['Authorization' => 'Bearer '.$host['token']],
        );

        $deniedApproval->assertConflict()->assertJsonPath('code', 'support_limit_reached');
        $this->assertNull($oldSupport['membership']->fresh()->revoked_at);
        $this->assertDatabaseHas('personal_access_tokens', [
            'id' => $oldSupport['accessToken']->id,
        ]);
        $this->assertSame(0, MonitorMembership::query()
            ->where('installation_id', $candidate['installationId'])
            ->count());

        $revokeOldSupport = $fixtures->requestJson(
            'DELETE',
            "/api/v1/monitors/{$host['monitor']->id}/supports/{$oldSupport['membership']->id}",
            '{}',
            ['Authorization' => 'Bearer '.$host['token']],
        );
        $revokeOldSupport->assertNoContent();
        $this->assertNotNull($oldSupport['membership']->fresh()->revoked_at);
        $oldSupportRequest = $fixtures->requestJson(
            'GET',
            '/api/v1/installation',
            headers: ['Authorization' => 'Bearer '.$oldSupport['token']],
        );
        $oldSupportRequest->assertUnauthorized()->assertJsonPath('code', 'unauthenticated');

        $approved = $fixtures->requestJson(
            'POST',
            "/api/v1/monitors/{$host['monitor']->id}/pairing-requests/{$candidate['requestId']}/approval",
            '{}',
            ['Authorization' => 'Bearer '.$host['token']],
        );

        $approved->assertOk();
        $this->assertSame(3, MonitorMembership::query()
            ->where('monitor_id', $host['monitor']->id)
            ->where('role', AccessRole::Support->value)
            ->whereNull('revoked_at')
            ->count());
        $candidateSupport = MonitorMembership::query()
            ->where('installation_id', $candidate['installationId'])
            ->where('role', AccessRole::Support->value)
            ->firstOrFail();
        $this->assertSame('Shared watch', Installation::query()
            ->findOrFail($candidate['installationId'])->label);
        $candidatePoll = $fixtures->requestJson(
            'GET',
            '/api/v1/pairing-requests/current',
            headers: ['Authorization' => 'Bearer '.$candidate['token']],
            remoteAddress: '198.51.100.75',
        );
        $candidatePoll->assertOk()->assertJsonPath('data.monitor.membershipId', $candidateSupport->id);
    }

    public static function expiredDecisionRoutes(): array
    {
        return [
            'approval at the exact request deadline' => ['approval', '2026-11-21 12:15:00 UTC'],
            'approval after the request deadline' => ['approval', '2026-11-21 12:15:01 UTC'],
            'rejection at the exact request deadline' => ['rejection', '2026-11-21 12:15:00 UTC'],
            'rejection after the request deadline' => ['rejection', '2026-11-21 12:15:01 UTC'],
        ];
    }

    #[DataProvider('expiredDecisionRoutes')]
    public function test_expired_decision_returns_410_and_commits_automatic_expiration(
        string $decision,
        string $decisionTime,
    ): void {
        $this->travelTo('2026-11-21 12:00:00 UTC');
        $fixtures = new AccessAndPairingFixtures($this);
        $host = $fixtures->createHost();
        $candidate = $this->createPendingPairingRequest(
            $fixtures,
            $host,
            '198.51.100.70',
        );
        $this->travelTo($decisionTime);

        $response = $fixtures->requestJson(
            'POST',
            "/api/v1/monitors/{$host['monitor']->id}/pairing-requests/{$candidate['requestId']}/{$decision}",
            '{}',
            ['Authorization' => 'Bearer '.$host['token']],
        );

        $response->assertGone()->assertJsonPath('code', 'pairing_request_unavailable');
        $expiredRequest = PairingRequest::query()->findOrFail($candidate['requestId']);
        $this->assertSame(PairingRequestStatus::Expired, $expiredRequest->status);
        $this->assertNull($expiredRequest->decision_actor_membership_id);
        $this->assertSame(now('UTC')->startOfSecond()->toISOString(), $expiredRequest->decided_at->toISOString());
        $this->assertSame(0, MonitorMembership::query()
            ->where('installation_id', $candidate['installationId'])
            ->count());

        $retry = $fixtures->requestJson(
            'POST',
            "/api/v1/monitors/{$host['monitor']->id}/pairing-requests/{$candidate['requestId']}/{$decision}",
            '{}',
            ['Authorization' => 'Bearer '.$host['token']],
        );
        $retry->assertGone()->assertJsonPath('code', 'pairing_request_unavailable');
        $this->assertSame(
            $expiredRequest->decided_at->toISOString(),
            PairingRequest::query()->findOrFail($candidate['requestId'])->decided_at->toISOString(),
        );
    }

    public function test_approved_retry_is_stable_when_full_after_deadline_and_does_not_reactivate_revoked_support(): void
    {
        $this->travelTo('2026-11-21 12:00:00 UTC');
        $fixtures = new AccessAndPairingFixtures($this);
        $host = $fixtures->createHost();
        $candidate = $this->createPendingPairingRequest(
            $fixtures,
            $host,
            '198.51.100.71',
        );
        $this->travelTo('2026-11-21 12:01:00 UTC');
        $approvalUri = "/api/v1/monitors/{$host['monitor']->id}/pairing-requests/{$candidate['requestId']}/approval";
        $approved = $fixtures->requestJson(
            'POST',
            $approvalUri,
            '{}',
            ['Authorization' => 'Bearer '.$host['token']],
        );
        $approved->assertOk();
        $approvalData = $approved->json('data');
        $supportMembership = MonitorMembership::query()->findOrFail($approvalData['membershipId']);
        $this->assertSame($host['membership']->id, PairingRequest::query()
            ->findOrFail($candidate['requestId'])->decision_actor_membership_id);

        $fixtures->createSupportInstallation($host['monitor']);
        $fixtures->createSupportInstallation($host['monitor']);
        $hostSwap = $fixtures->requestJson(
            'POST',
            '/api/v1/owner/host-activations',
            '{"confirmation":true,"expectedGeneration":"1"}',
            ['Authorization' => 'Bearer '.FakeOwnerIdentityVerifier::TEST_BEARER_TOKEN],
            '192.0.2.12',
        );
        $hostSwap->assertOk();
        $currentHostToken = $hostSwap->json('data.accessToken');
        $this->travelTo('2026-11-21 12:20:00 UTC');

        $retry = $fixtures->requestJson(
            'POST',
            $approvalUri,
            '{}',
            ['Authorization' => 'Bearer '.$currentHostToken],
        );

        $retry->assertOk()->assertExactJson(['data' => $approvalData]);
        $this->assertSame(3, MonitorMembership::query()
            ->where('monitor_id', $host['monitor']->id)
            ->where('role', AccessRole::Support->value)
            ->whereNull('revoked_at')
            ->count());
        $decidedAt = PairingRequest::query()->findOrFail($candidate['requestId'])->decided_at;

        $revoke = $fixtures->requestJson(
            'DELETE',
            "/api/v1/monitors/{$host['monitor']->id}/supports/{$supportMembership->id}",
            '{}',
            ['Authorization' => 'Bearer '.$currentHostToken],
        );
        $revoke->assertNoContent();

        $terminalRetry = $fixtures->requestJson(
            'POST',
            $approvalUri,
            '{}',
            ['Authorization' => 'Bearer '.$currentHostToken],
        );

        $terminalRetry->assertConflict()->assertJsonPath('code', 'pairing_request_terminal');
        $this->assertNotNull($supportMembership->fresh()->revoked_at);
        $this->assertSame(1, MonitorMembership::query()
            ->where('id', $supportMembership->id)
            ->count());
        $this->assertSame($decidedAt->toISOString(), PairingRequest::query()
            ->findOrFail($candidate['requestId'])->decided_at->toISOString());
        $this->assertDatabaseMissing('personal_access_tokens', [
            'tokenable_id' => $candidate['installationId'],
        ]);
    }

    public function test_host_revokes_a_support_membership_and_allows_an_idempotent_retry(): void
    {
        $fixtures = new AccessAndPairingFixtures($this);
        $host = $fixtures->createHost();
        $support = $fixtures->createSupportInstallation($host['monitor']);
        $otherSupport = $fixtures->createSupportInstallation($host['monitor']);

        $response = $fixtures->requestJson(
            'DELETE',
            "/api/v1/monitors/{$host['monitor']->id}/supports/{$support['membership']->id}",
            '{}',
            ['Authorization' => 'Bearer '.$host['token']],
        );

        $response->assertNoContent();
        $revokedAt = $support['membership']->fresh()->revoked_at;
        $this->assertNotNull($revokedAt);

        $retry = $fixtures->requestJson(
            'DELETE',
            "/api/v1/monitors/{$host['monitor']->id}/supports/{$support['membership']->id}",
            '{}',
            ['Authorization' => 'Bearer '.$host['token']],
        );
        $retry->assertNoContent();

        $this->assertSame(
            $revokedAt->toISOString(),
            $support['membership']->fresh()->revoked_at->toISOString(),
        );
        $this->assertDatabaseMissing('personal_access_tokens', [
            'id' => $support['accessToken']->id,
        ]);
        $this->assertDatabaseHas('personal_access_tokens', ['id' => $host['accessToken']->id]);
        $this->assertDatabaseHas('monitor_memberships', [
            'id' => $otherSupport['membership']->id,
            'monitor_id' => $host['monitor']->id,
            'installation_id' => $otherSupport['installation']->id,
            'role' => AccessRole::Support->value,
            'revoked_at' => null,
        ]);
        $this->assertDatabaseHas('personal_access_tokens', [
            'id' => $otherSupport['accessToken']->id,
            'tokenable_id' => $otherSupport['installation']->id,
            'expires_at' => null,
        ]);

        $otherSupportContext = $fixtures->requestJson(
            'GET',
            '/api/v1/installation',
            headers: ['Authorization' => 'Bearer '.$otherSupport['token']],
        );

        $otherSupportContext->assertOk()->assertExactJson([
            'data' => [
                'installationId' => $otherSupport['installation']->id,
                'monitorId' => $host['monitor']->id,
                'membershipId' => $otherSupport['membership']->id,
                'role' => 'Support',
                'status' => 'Active',
                'monitorGeneration' => '1',
            ],
        ]);
    }

    /**
     * @param  array{monitor: Monitor, token: string}  $host
     * @return array{requestId: string, installationId: string, token: string}
     */
    private function createPendingPairingRequest(
        AccessAndPairingFixtures $fixtures,
        array $host,
        string $remoteAddress,
        string $installationLabel = 'Candidate device',
    ): array {
        $invitation = $fixtures->requestJson(
            'POST',
            "/api/v1/monitors/{$host['monitor']->id}/invitations",
            '{}',
            ['Authorization' => 'Bearer '.$host['token']],
        );
        $invitation->assertCreated();
        $redeemed = $fixtures->requestJson(
            'POST',
            '/api/v1/pairing-requests',
            json_encode([
                'invitationSecret' => $invitation->json('data.invitationSecret'),
                'installationLabel' => $installationLabel,
            ], JSON_THROW_ON_ERROR),
            remoteAddress: $remoteAddress,
        );
        $redeemed->assertCreated();

        return [
            'requestId' => $redeemed->json('data.requestId'),
            'installationId' => $redeemed->json('data.installationId'),
            'token' => $redeemed->json('data.accessToken'),
        ];
    }

    private function createPairingRequestFixture(
        Monitor $monitor,
        PairingRequestStatus $status,
        int $generation,
        \DateTimeInterface $requestExpiresAt,
        \DateTimeInterface $createdAt,
        string $label,
    ): PairingRequest {
        $invitation = Invitation::factory()->create([
            'monitor_id' => $monitor->id,
            'issuing_generation' => $generation,
            'consumed_at' => now('UTC'),
            'expires_at' => now('UTC')->addHour(),
        ]);
        $installation = Installation::factory()->create(['label' => $label]);
        $pairingRequest = PairingRequest::factory()->create([
            'monitor_id' => $monitor->id,
            'invitation_id' => $invitation->id,
            'installation_id' => $installation->id,
            'status' => $status,
            'request_expires_at' => $requestExpiresAt,
        ]);
        $pairingRequest->created_at = $createdAt;
        $pairingRequest->save();

        return $pairingRequest;
    }
}
