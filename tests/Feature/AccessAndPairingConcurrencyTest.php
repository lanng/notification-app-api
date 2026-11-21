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
use App\Support\AccessAndPairing\AccessAndPairing;
use App\Support\AccessAndPairing\VerifiedOwnerIdentity;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use Laravel\Sanctum\PersonalAccessToken;
use RuntimeException;
use Symfony\Component\Process\Process;
use Tests\Support\AccessAndPairingFixtures;
use Tests\Support\SafePostgresTestingDatabase;
use Tests\TestCase;
use Throwable;

final class AccessAndPairingConcurrencyTest extends TestCase
{
    private const FIXED_UTC_TIME = '2026-11-21 12:00:00 UTC';

    private const LOCK_WAIT_TIMEOUT_SECONDS = 12.0;

    private const CHILD_TIMEOUT_SECONDS = 30.0;

    /**
     * @var array{
     *     users: list<int|string>,
     *     monitors: list<string>,
     *     installations: list<string>,
     *     memberships: list<string>,
     *     invitations: list<string>,
     *     pairingRequests: list<string>,
     *     accessTokens: list<int>
     * }
     */
    private array $ownedRecords = [
        'users' => [],
        'monitors' => [],
        'installations' => [],
        'memberships' => [],
        'invitations' => [],
        'pairingRequests' => [],
        'accessTokens' => [],
    ];

    /**
     * @var array<string, array{projectId: string, firebaseUid: string}>
     */
    private array $ownerIdentities = [];

    /**
     * @var array<string, array{
     *     process: Process,
     *     applicationName: string,
     *     resultPath: string,
     *     configCachePath: string
     * }>
     */
    private array $workers = [];

    /**
     * @var array<string, array{
     *     pid: int,
     *     parentPid: int,
     *     applicationName: string,
     *     expectedTable: string,
     *     waitEvent: string,
     *     blockingPids: list<int>,
     *     blockingPaths: list<list<int>>
     * }>
     */
    private array $lockWitnesses = [];

    private ?string $runId = null;

    private ?string $runDirectory = null;

    private int $parentTransactionLevel = 0;

    private bool $parentTransactionOpen = false;

    private ?int $parentBackendPid = null;

    protected function setUp(): void
    {
        parent::setUp();

        SafePostgresTestingDatabase::assertSafe($this->app);

        $this->runId = bin2hex(random_bytes(6));
        $this->runDirectory = '/tmp/opencode/tag-alert/access-pairing/'.$this->runId;

        if (file_exists($this->runDirectory)) {
            throw new RuntimeException('The unique access-pairing test directory already exists.');
        }

        if (! mkdir($this->runDirectory, 0700, true) && ! is_dir($this->runDirectory)) {
            throw new RuntimeException('The access-pairing test directory could not be created.');
        }

        $migrationExitCode = Artisan::call('migrate', [
            '--database' => 'pgsql',
            '--force' => true,
            '--no-interaction' => true,
        ]);

        $this->assertSame(0, $migrationExitCode, 'The guarded PostgreSQL test migrations must be available.');
    }

    protected function tearDown(): void
    {
        try {
            $this->stopWorkers();
            $this->rollbackParentTransaction();
            $this->cleanupOwnedRecords();
            $this->cleanupWorkerArtifacts();
        } finally {
            parent::tearDown();
        }
    }

    public function test_only_one_of_two_concurrent_redemptions_consumes_an_invitation(): void
    {
        $this->travelTo(self::FIXED_UTC_TIME);
        $fixtures = new AccessAndPairingFixtures($this);
        $host = $this->createHost($fixtures, 'redemption');
        $invitation = $this->createInvitation($fixtures, $host);

        $this->beginMonitorBarrier($host['monitor']->id);
        $this->startWorker('redemption-one', [
            'operation' => 'redeem',
            'invitationSecret' => $invitation['secret'],
            'installationLabel' => 'race-redemption-one',
            'remoteAddress' => '192.0.2.101',
        ]);
        $this->startWorker('redemption-two', [
            'operation' => 'redeem',
            'invitationSecret' => $invitation['secret'],
            'installationLabel' => 'race-redemption-two',
            'remoteAddress' => '192.0.2.102',
        ]);

        $witnesses = $this->waitForLockWitnesses(
            ['redemption-one', 'redemption-two'],
            'monitors',
        );
        $this->assertDistinctLockWitnesses($witnesses);
        $this->commitParentTransaction();

        $results = $this->awaitWorkers(['redemption-one', 'redemption-two']);
        $statuses = array_column($results, 'status');
        sort($statuses);

        $this->assertSame([201, 410], $statuses);
        $winner = collect($results)->firstWhere('status', 201);
        $unavailable = collect($results)->firstWhere('status', 410);

        $this->assertIsArray($winner);
        $this->assertIsArray($unavailable);
        $this->assertSame('Pending', $winner['response']['data']['status']);
        $this->assertSame('invitation_unavailable', $unavailable['response']['code']);

        $persistedInvitation = Invitation::query()->findOrFail($invitation['id']);
        $requests = PairingRequest::query()
            ->where('invitation_id', $invitation['id'])
            ->get();
        $this->assertNotNull($persistedInvitation->consumed_at);
        $this->assertCount(1, $requests);

        $request = $requests->sole();
        $this->remember('pairingRequests', $request->id);
        $this->remember('installations', $request->installation_id);
        $this->assertSame($winner['response']['data']['requestId'], $request->id);
        $this->assertSame($winner['response']['data']['installationId'], $request->installation_id);
        $this->assertSame(PairingRequestStatus::Pending, $request->status);
        $this->assertSame(0, MonitorMembership::query()
            ->where('monitor_id', $host['monitor']->id)
            ->where('installation_id', $request->installation_id)
            ->count());
        $this->assertSame(1, PersonalAccessToken::query()
            ->where('tokenable_type', (new Installation)->getMorphClass())
            ->where('tokenable_id', $request->installation_id)
            ->where('name', 'pairing-pending')
            ->count());
        $this->assertSame(1, Installation::query()
            ->whereIn('label', ['race-redemption-one', 'race-redemption-two'])
            ->count());
    }

    public function test_concurrent_approvals_enforce_the_three_support_limit_and_preserve_the_winning_pat(): void
    {
        $this->travelTo(self::FIXED_UTC_TIME);
        $fixtures = new AccessAndPairingFixtures($this);
        $host = $this->createHost($fixtures, 'support-cap');
        $existingSupports = [
            $this->createSupport($fixtures, $host),
            $this->createSupport($fixtures, $host),
        ];
        $firstCandidate = $this->createPendingRequest($fixtures, $host, '192.0.2.111');
        $secondCandidate = $this->createPendingRequest($fixtures, $host, '192.0.2.112');

        $this->beginMonitorBarrier($host['monitor']->id);
        $this->startWorker('approval-one', [
            'operation' => 'approve',
            'monitorId' => $host['monitor']->id,
            'requestId' => $firstCandidate['requestId'],
            'hostToken' => $host['token'],
            'remoteAddress' => '198.51.100.111',
        ]);
        $this->startWorker('approval-two', [
            'operation' => 'approve',
            'monitorId' => $host['monitor']->id,
            'requestId' => $secondCandidate['requestId'],
            'hostToken' => $host['token'],
            'remoteAddress' => '198.51.100.112',
        ]);

        $witnesses = $this->waitForLockWitnesses(['approval-one', 'approval-two'], 'monitors');
        $this->assertDistinctLockWitnesses($witnesses);
        $this->commitParentTransaction();

        $results = $this->awaitWorkers(['approval-one', 'approval-two']);
        $statuses = array_column($results, 'status');
        sort($statuses);

        $this->assertSame([200, 409], $statuses);
        $approved = collect($results)->first(
            static fn (array $result): bool => $result['status'] === 200,
        );
        $refused = collect($results)->first(
            static fn (array $result): bool => $result['status'] === 409,
        );
        $this->assertIsArray($approved);
        $this->assertIsArray($refused);
        $this->assertSame('support_limit_reached', $refused['response']['code']);

        $activeSupportCount = MonitorMembership::query()
            ->where('monitor_id', $host['monitor']->id)
            ->where('role', AccessRole::Support->value)
            ->whereNotNull('approved_at')
            ->whereNull('revoked_at')
            ->count();
        $this->assertSame(3, $activeSupportCount);

        $winningRequest = PairingRequest::query()->findOrFail($approved['response']['data']['requestId']);
        $losingCandidate = $winningRequest->id === $firstCandidate['requestId']
            ? $secondCandidate
            : $firstCandidate;
        $winningCandidate = $winningRequest->id === $firstCandidate['requestId']
            ? $firstCandidate
            : $secondCandidate;
        $this->assertSame(PairingRequestStatus::Approved, $winningRequest->status);
        $this->assertSame($host['membership']->id, $winningRequest->decision_actor_membership_id);
        $this->assertNotNull($winningRequest->decided_at);
        $this->assertSame(
            $approved['response']['data']['decidedAt'],
            $winningRequest->decided_at->getTimestamp() * 1000,
        );
        $this->assertSame(
            2,
            PersonalAccessToken::query()
                ->where('tokenable_type', (new Installation)->getMorphClass())
                ->whereIn('tokenable_id', [$firstCandidate['installationId'], $secondCandidate['installationId']])
                ->count(),
        );
        $this->assertSame(1, MonitorMembership::query()
            ->where('monitor_id', $host['monitor']->id)
            ->where('installation_id', $winningCandidate['installationId'])
            ->where('role', AccessRole::Support->value)
            ->whereNull('revoked_at')
            ->count());

        $winningToken = PersonalAccessToken::query()->findOrFail($winningCandidate['tokenId']);
        $this->assertSame($winningCandidate['tokenId'], $winningToken->id);
        $this->assertSame($winningCandidate['tokenHash'], $winningToken->token);
        $this->assertNull($winningToken->expires_at);
        $this->assertSame(1, PersonalAccessToken::query()
            ->where('tokenable_type', (new Installation)->getMorphClass())
            ->where('tokenable_id', $winningCandidate['installationId'])
            ->count());

        $losingRequest = PairingRequest::query()->findOrFail($losingCandidate['requestId']);
        $this->assertSame(PairingRequestStatus::Pending, $losingRequest->status);
        $losingToken = PersonalAccessToken::query()->findOrFail($losingCandidate['tokenId']);
        $this->assertSame($losingCandidate['tokenId'], $losingToken->id);
        $this->assertSame($losingCandidate['tokenHash'], $losingToken->token);
        $this->assertSame($losingCandidate['tokenExpiresAt'], $losingToken->expires_at?->toISOString());
        $this->assertGreaterThan(now('UTC'), $losingToken->expires_at);
        foreach ($existingSupports as $existingSupport) {
            $this->assertSame(1, MonitorMembership::query()
                ->whereKey($existingSupport['membership']->id)
                ->whereNull('revoked_at')
                ->count());
            $this->assertDatabaseHas('personal_access_tokens', [
                'id' => $existingSupport['accessToken']->id,
            ]);
        }
    }

    public function test_concurrent_approval_and_rejection_produce_one_terminal_decision(): void
    {
        $this->travelTo(self::FIXED_UTC_TIME);
        $fixtures = new AccessAndPairingFixtures($this);
        $host = $this->createHost($fixtures, 'opposing-decisions');
        $candidate = $this->createPendingRequest($fixtures, $host, '192.0.2.121');

        $this->beginMonitorBarrier($host['monitor']->id);
        $this->startWorker('decision-approval', [
            'operation' => 'approve',
            'monitorId' => $host['monitor']->id,
            'requestId' => $candidate['requestId'],
            'hostToken' => $host['token'],
            'remoteAddress' => '198.51.100.121',
        ]);
        $this->startWorker('decision-rejection', [
            'operation' => 'reject',
            'monitorId' => $host['monitor']->id,
            'requestId' => $candidate['requestId'],
            'hostToken' => $host['token'],
            'remoteAddress' => '198.51.100.122',
        ]);

        $witnesses = $this->waitForLockWitnesses(
            ['decision-approval', 'decision-rejection'],
            'monitors',
        );
        $this->assertDistinctLockWitnesses($witnesses);
        $this->commitParentTransaction();

        $results = $this->awaitWorkers(['decision-approval', 'decision-rejection']);
        $statuses = array_column($results, 'status');
        sort($statuses);

        $this->assertSame([200, 409], $statuses);
        $winner = collect($results)->first(
            static fn (array $result): bool => $result['status'] === 200,
        );
        $loser = collect($results)->first(
            static fn (array $result): bool => $result['status'] === 409,
        );
        $this->assertIsArray($winner);
        $this->assertIsArray($loser);
        $this->assertSame('pairing_request_terminal', $loser['response']['code']);

        $request = PairingRequest::query()->findOrFail($candidate['requestId']);
        $this->assertContains($request->status, [
            PairingRequestStatus::Approved,
            PairingRequestStatus::Rejected,
        ]);
        $this->assertSame($winner['response']['data']['status'], $request->status->value);
        $this->assertNotNull($request->decided_at);
        $this->assertSame($host['membership']->id, $request->decision_actor_membership_id);
        $this->assertSame(
            $winner['response']['data']['decidedAt'],
            $request->decided_at->getTimestamp() * 1000,
        );

        $supportCount = MonitorMembership::query()
            ->where('monitor_id', $host['monitor']->id)
            ->where('installation_id', $candidate['installationId'])
            ->where('role', AccessRole::Support->value)
            ->count();
        $candidateToken = PersonalAccessToken::query()->find($candidate['tokenId']);

        if ($request->status === PairingRequestStatus::Approved) {
            $this->assertSame(1, $supportCount);
            $this->assertInstanceOf(PersonalAccessToken::class, $candidateToken);
            $this->assertSame($candidate['tokenId'], $candidateToken->id);
            $this->assertSame($candidate['tokenHash'], $candidateToken->token);
            $this->assertNull($candidateToken->expires_at);
            $this->assertSame(1, PersonalAccessToken::query()
                ->where('tokenable_type', (new Installation)->getMorphClass())
                ->where('tokenable_id', $candidate['installationId'])
                ->count());
        } else {
            $this->assertSame(0, $supportCount);
            $this->assertNull($candidateToken);
            $this->assertSame(0, PersonalAccessToken::query()
                ->where('tokenable_type', (new Installation)->getMorphClass())
                ->where('tokenable_id', $candidate['installationId'])
                ->count());
        }
    }

    public function test_concurrent_first_owner_activations_resolve_the_unique_identity_race(): void
    {
        $this->travelTo(self::FIXED_UTC_TIME);
        $projectId = 'ap8-project-'.$this->runId;
        $firebaseUid = 'ap8-owner-'.$this->runId;
        config([
            'access_pairing.owner.firebase_project_id' => $projectId,
            'access_pairing.owner.firebase_uid' => $firebaseUid,
        ]);
        $this->rememberOwnerIdentity($projectId, $firebaseUid);

        $this->assertFalse(User::query()
            ->where('firebase_project_id', $projectId)
            ->where('firebase_uid', $firebaseUid)
            ->exists());

        $this->beginParentTransaction();
        $owner = User::query()->create([
            'firebase_project_id' => $projectId,
            'firebase_uid' => $firebaseUid,
        ]);
        $this->remember('users', $owner->id);

        $this->startWorker('first-activation-one', [
            'operation' => 'activate',
            'expectedGeneration' => '0',
            'remoteAddress' => '198.51.100.131',
        ]);
        $this->startWorker('first-activation-two', [
            'operation' => 'activate',
            'expectedGeneration' => '0',
            'remoteAddress' => '198.51.100.132',
        ]);

        $witnesses = $this->waitForLockWitnesses(
            ['first-activation-one', 'first-activation-two'],
            'users',
        );
        $this->assertDistinctLockWitnesses($witnesses);
        $this->assertSame(
            ['transactionid'],
            array_values(array_unique(array_column($witnesses, 'waitEvent'))),
        );
        $this->commitParentTransaction();

        $results = $this->awaitWorkers(['first-activation-one', 'first-activation-two']);
        $statuses = array_column($results, 'status');
        sort($statuses);

        $this->assertSame([201, 409], $statuses);
        $winner = collect($results)->firstWhere('status', 201);
        $loser = collect($results)->firstWhere('status', 409);
        $this->assertIsArray($winner);
        $this->assertIsArray($loser);
        $this->assertSame('generation_conflict', $loser['response']['code']);

        $this->assertSame(1, User::query()
            ->where('firebase_project_id', $projectId)
            ->where('firebase_uid', $firebaseUid)
            ->count());
        $monitor = Monitor::query()->where('user_id', $owner->id)->sole();
        $this->remember('monitors', $monitor->id);
        $this->remember('installations', $winner['response']['data']['installationId']);
        $this->remember('memberships', $winner['response']['data']['membershipId']);

        $this->assertSame(1, $monitor->host_generation);
        $this->assertSame(1, MonitorMembership::query()
            ->where('monitor_id', $monitor->id)
            ->where('role', AccessRole::Host->value)
            ->whereNotNull('approved_at')
            ->whereNull('revoked_at')
            ->count());
        $this->assertSame(1, MonitorMembership::query()->where('monitor_id', $monitor->id)->count());
        $this->assertSame(1, Installation::query()
            ->whereIn('id', MonitorMembership::query()
                ->where('monitor_id', $monitor->id)
                ->select('installation_id'))
            ->count());
        $this->assertSame(1, PersonalAccessToken::query()
            ->where('tokenable_type', (new Installation)->getMorphClass())
            ->where('tokenable_id', $winner['response']['data']['installationId'])
            ->count());
    }

    public function test_approved_support_and_its_pat_survive_a_later_host_swap(): void
    {
        $this->travelTo(self::FIXED_UTC_TIME);
        $fixtures = new AccessAndPairingFixtures($this);
        $host = $this->createHost($fixtures, 'approval-before-swap');
        $candidate = $this->createPendingRequest($fixtures, $host, '192.0.2.141');

        $this->beginMonitorBarrier($host['monitor']->id);
        $this->startWorker('approval-before-swap', [
            'operation' => 'approve',
            'monitorId' => $host['monitor']->id,
            'requestId' => $candidate['requestId'],
            'hostToken' => $host['token'],
            'remoteAddress' => '198.51.100.141',
        ]);

        $witnesses = $this->waitForLockWitnesses(['approval-before-swap'], 'monitors');
        $this->assertDistinctLockWitnesses($witnesses);
        $this->commitParentTransaction();

        $approval = $this->awaitWorkers(['approval-before-swap'])['approval-before-swap'];
        $this->assertSame(200, $approval['status']);
        $this->assertSame('Approved', $approval['response']['data']['status']);
        $candidateToken = PersonalAccessToken::query()->findOrFail($candidate['tokenId']);
        $candidateTokenHash = $candidateToken->token;
        $this->assertNull($candidateToken->expires_at);

        $this->startWorker('host-swap-after-approval', [
            'operation' => 'activate',
            'expectedGeneration' => '1',
            'remoteAddress' => '198.51.100.142',
        ]);
        $activation = $this->awaitWorkers(['host-swap-after-approval'])['host-swap-after-approval'];

        $this->assertSame(200, $activation['status']);
        $this->assertSame('2', $activation['response']['data']['generation']);
        $this->assertSame(PairingRequestStatus::Approved, PairingRequest::query()
            ->findOrFail($candidate['requestId'])
            ->status);
        $this->assertSame(1, MonitorMembership::query()
            ->where('monitor_id', $host['monitor']->id)
            ->where('installation_id', $candidate['installationId'])
            ->where('role', AccessRole::Support->value)
            ->whereNull('revoked_at')
            ->count());
        $candidateToken->refresh();
        $this->assertSame($candidate['tokenId'], $candidateToken->id);
        $this->assertSame($candidateTokenHash, $candidateToken->token);
        $this->assertNull($candidateToken->expires_at);
        $this->assertDatabaseMissing('personal_access_tokens', ['id' => $host['accessToken']->id]);
        $this->assertSame(2, $host['monitor']->fresh()->host_generation);
    }

    public function test_host_swap_wins_against_a_waiting_old_host_approval(): void
    {
        $this->travelTo(self::FIXED_UTC_TIME);
        $fixtures = new AccessAndPairingFixtures($this);
        $host = $this->createHost($fixtures, 'swap-before-approval');
        $existingSupport = $this->createSupport($fixtures, $host);
        $candidate = $this->createPendingRequest($fixtures, $host, '192.0.2.151');

        $this->beginMonitorBarrier($host['monitor']->id);
        $this->startWorker('old-host-approval', [
            'operation' => 'approve',
            'monitorId' => $host['monitor']->id,
            'requestId' => $candidate['requestId'],
            'hostToken' => $host['token'],
            'remoteAddress' => '198.51.100.151',
        ]);

        $witnesses = $this->waitForLockWitnesses(['old-host-approval'], 'monitors');
        $this->assertDistinctLockWitnesses($witnesses);

        $identity = new VerifiedOwnerIdentity(
            (string) config('access_pairing.owner.firebase_project_id'),
            (string) config('access_pairing.owner.firebase_uid'),
            'google.com',
            now('UTC')->getTimestamp(),
        );
        $activation = app(AccessAndPairing::class)->activateHost($identity, true, '1');
        $this->assertFalse($activation['firstActivation']);
        $this->remember('installations', $activation['data']['installationId']);
        $this->remember('memberships', $activation['data']['membershipId']);
        $newHostToken = PersonalAccessToken::findToken($activation['data']['accessToken']);

        if (! $newHostToken instanceof PersonalAccessToken) {
            throw new RuntimeException('The actual host-swap operation did not persist its host credential.');
        }

        $this->remember('accessTokens', $newHostToken->id);
        $this->commitParentTransaction();

        $approval = $this->awaitWorkers(['old-host-approval'])['old-host-approval'];
        // This request passed host preflight before waiting; the 401 is the post-lock domain PAT recheck.
        $this->assertSame(401, $approval['status']);
        $this->assertSame('access_unauthenticated', $approval['response']['code']);

        $monitor = $host['monitor']->fresh();
        $this->assertSame(2, $monitor->host_generation);
        $this->assertSame(1, MonitorMembership::query()
            ->where('monitor_id', $monitor->id)
            ->where('installation_id', $activation['data']['installationId'])
            ->where('role', AccessRole::Host->value)
            ->where('generation', 2)
            ->whereNull('revoked_at')
            ->count());
        $this->assertDatabaseMissing('personal_access_tokens', ['id' => $host['accessToken']->id]);
        $this->assertSame(PairingRequestStatus::Cancelled, PairingRequest::query()
            ->findOrFail($candidate['requestId'])
            ->status);
        $cancelledRequest = PairingRequest::query()->findOrFail($candidate['requestId']);
        $this->assertNull($cancelledRequest->decision_actor_membership_id);
        $this->assertNotNull($cancelledRequest->decided_at);
        $this->assertSame(0, MonitorMembership::query()
            ->where('monitor_id', $monitor->id)
            ->where('installation_id', $candidate['installationId'])
            ->where('role', AccessRole::Support->value)
            ->count());
        $this->assertDatabaseMissing('personal_access_tokens', ['id' => $candidate['tokenId']]);
        $this->assertSame(1, MonitorMembership::query()
            ->whereKey($existingSupport['membership']->id)
            ->whereNull('revoked_at')
            ->count());
        $this->assertDatabaseHas('personal_access_tokens', ['id' => $existingSupport['accessToken']->id]);
    }

    private function createHost(AccessAndPairingFixtures $fixtures, string $case): array
    {
        $firebaseUid = 'ap8-'.$this->runId.'-'.$case;
        $this->rememberOwnerIdentity('fixture-project', $firebaseUid);
        $host = $fixtures->createHost($firebaseUid);
        $this->remember('users', $host['monitor']->user_id);
        $this->remember('monitors', $host['monitor']->id);
        $this->remember('installations', $host['installation']->id);
        $this->remember('memberships', $host['membership']->id);
        $this->remember('accessTokens', $host['accessToken']->id);

        return $host;
    }

    /**
     * @param  array{monitor: Monitor, installation: Installation, token: string}  $host
     * @return array{id: string, secret: string}
     */
    private function createInvitation(AccessAndPairingFixtures $fixtures, array $host): array
    {
        $response = $fixtures->requestJson(
            'POST',
            "/api/v1/monitors/{$host['monitor']->id}/invitations",
            '{}',
            ['Authorization' => 'Bearer '.$host['token']],
        );
        $response->assertCreated();

        $invitationId = $response->json('data.id');
        $secret = $response->json('data.invitationSecret');
        $this->remember('invitations', $invitationId);

        return [
            'id' => $invitationId,
            'secret' => $secret,
        ];
    }

    /**
     * @param  array{monitor: Monitor}  $host
     * @return array{
     *     installation: Installation,
     *     membership: MonitorMembership,
     *     token: string,
     *     accessToken: PersonalAccessToken
     * }
     */
    private function createSupport(AccessAndPairingFixtures $fixtures, array $host): array
    {
        $support = $fixtures->createSupportInstallation($host['monitor']);
        $this->remember('installations', $support['installation']->id);
        $this->remember('memberships', $support['membership']->id);
        $this->remember('accessTokens', $support['accessToken']->id);

        return $support;
    }

    /**
     * @param  array{monitor: Monitor, installation: Installation, token: string, membership: MonitorMembership}  $host
     * @return array{
     *     requestId: string,
     *     installationId: string,
     *     tokenId: int,
     *     tokenHash: string,
     *     tokenExpiresAt: string
     * }
     */
    private function createPendingRequest(
        AccessAndPairingFixtures $fixtures,
        array $host,
        string $remoteAddress,
    ): array {
        $invitation = $this->createInvitation($fixtures, $host);
        $response = $fixtures->requestJson(
            'POST',
            '/api/v1/pairing-requests',
            json_encode([
                'invitationSecret' => $invitation['secret'],
                'installationLabel' => 'ap8-candidate-'.$this->runId,
            ], JSON_THROW_ON_ERROR),
            remoteAddress: $remoteAddress,
        );
        $requestId = $response->json('data.requestId');
        $installationId = $response->json('data.installationId');

        if (is_string($requestId)) {
            $this->remember('pairingRequests', $requestId);
        }

        if (is_string($installationId)) {
            $this->remember('installations', $installationId);
        }

        $response->assertCreated();

        if (! is_string($requestId) || ! is_string($installationId)) {
            throw new RuntimeException('The pending pairing fixture response was incomplete.');
        }

        $pendingToken = PersonalAccessToken::findToken($response->json('data.accessToken'));

        if (! $pendingToken instanceof PersonalAccessToken) {
            throw new RuntimeException('The pending pairing fixture did not create its access token.');
        }

        $this->remember('accessTokens', $pendingToken->id);

        return [
            'requestId' => $requestId,
            'installationId' => $installationId,
            'tokenId' => $pendingToken->id,
            'tokenHash' => $pendingToken->token,
            'tokenExpiresAt' => $pendingToken->expires_at?->toISOString() ?? '',
        ];
    }

    /**
     * @param  'users'|'monitors'|'installations'|'memberships'|'invitations'|'pairingRequests'|'accessTokens'  $type
     */
    private function remember(string $type, int|string $id): void
    {
        if (! in_array($id, $this->ownedRecords[$type], true)) {
            $this->ownedRecords[$type][] = $id;
        }
    }

    private function rememberOwnerIdentity(string $projectId, string $firebaseUid): void
    {
        $this->ownerIdentities[$projectId."\0".$firebaseUid] = [
            'projectId' => $projectId,
            'firebaseUid' => $firebaseUid,
        ];
    }

    private function beginMonitorBarrier(string $monitorId): void
    {
        $this->beginParentTransaction();

        $monitor = Monitor::query()
            ->whereKey($monitorId)
            ->lockForUpdate()
            ->first();

        if (! $monitor instanceof Monitor) {
            throw new RuntimeException('The expected monitor lock row does not exist.');
        }
    }

    private function beginParentTransaction(): void
    {
        $connection = DB::connection('pgsql');
        $this->parentTransactionLevel = $connection->transactionLevel();

        if ($this->parentTransactionLevel !== 0) {
            throw new RuntimeException('The concurrency test cannot run inside an outer transaction.');
        }

        $connection->beginTransaction();
        $this->parentTransactionOpen = true;
        $this->parentBackendPid = (int) $connection->selectOne(
            'select pg_backend_pid() as pid',
        )->pid;
    }

    /**
     * @param  array<string, mixed>  $input
     */
    private function startWorker(string $workerName, array $input): void
    {
        if (isset($this->workers[$workerName])) {
            throw new RuntimeException('The access-pairing worker name is not unique.');
        }

        $runDirectory = $this->runDirectory;

        if ($runDirectory === null) {
            throw new RuntimeException('The access-pairing test directory is unavailable.');
        }

        $applicationName = 'tag-alert-ap-'.$this->runId.'-'.$workerName;
        $configCachePath = $runDirectory.'/'.$workerName.'-missing.php';
        $resultPath = $runDirectory.'/'.$workerName.'-result.json';

        if (strlen($applicationName) > 63 || file_exists($configCachePath) || file_exists($resultPath)) {
            throw new RuntimeException('The unique access-pairing worker environment is unsafe.');
        }

        $databaseConfig = config('database.connections.pgsql');
        $environment = [
            'APP_ENV' => 'testing',
            'APP_CONFIG_CACHE' => $configCachePath,
            'APP_KEY' => (string) config('app.key'),
            'DB_CONNECTION' => 'pgsql',
            'DB_HOST' => (string) $databaseConfig['host'],
            'DB_PORT' => (string) $databaseConfig['port'],
            'DB_DATABASE' => (string) $databaseConfig['database'],
            'DB_USERNAME' => (string) $databaseConfig['username'],
            'DB_PASSWORD' => (string) $databaseConfig['password'],
            'DB_URL' => '',
            'CACHE_STORE' => 'array',
            'SESSION_DRIVER' => 'array',
            'ACCESS_PAIRING_OWNER_FIREBASE_PROJECT_ID' => (string) config(
                'access_pairing.owner.firebase_project_id',
            ),
            'ACCESS_PAIRING_OWNER_FIREBASE_UID' => (string) config('access_pairing.owner.firebase_uid'),
            'AP_WORKER_FIXED_UTC' => self::FIXED_UTC_TIME,
            'AP_WORKER_OWNER_AUTH_TIME' => (string) now('UTC')->getTimestamp(),
            'AP_WORKER_APPLICATION_NAME' => $applicationName,
            'AP_WORKER_INPUT' => json_encode($input, JSON_THROW_ON_ERROR),
            'AP_WORKER_RESULT_PATH' => $resultPath,
            'PGAPPNAME' => $applicationName,
        ];
        $process = new Process([
            PHP_BINARY,
            base_path('vendor/bin/phpunit'),
            '--configuration',
            base_path('phpunit.xml'),
            base_path('tests/Support/AccessAndPairingWorkerTest.php'),
        ], base_path(), $environment);
        $process->setTimeout(self::CHILD_TIMEOUT_SECONDS);
        $process->start();

        $this->workers[$workerName] = [
            'process' => $process,
            'applicationName' => $applicationName,
            'resultPath' => $resultPath,
            'configCachePath' => $configCachePath,
        ];
    }

    /**
     * @param  list<string>  $workerNames
     * @return array<string, array{
     *     pid: int,
     *     parentPid: int,
     *     applicationName: string,
     *     expectedTable: string,
     *     waitEvent: string,
     *     blockingPids: list<int>,
     *     blockingPaths: list<list<int>>
     * }>
     */
    private function waitForLockWitnesses(
        array $workerNames,
        string $expectedTable,
    ): array {
        if ($this->parentBackendPid === null) {
            throw new RuntimeException('The PostgreSQL lock barrier has no parent backend.');
        }

        if (! in_array($expectedTable, ['monitors', 'users'], true) || $workerNames === []) {
            throw new RuntimeException('The PostgreSQL lock barrier received an invalid witness batch.');
        }

        $applicationNames = [];

        foreach ($workerNames as $workerName) {
            $worker = $this->workers[$workerName] ?? null;

            if (! is_array($worker)) {
                throw new RuntimeException('A PostgreSQL concurrency worker was not started.');
            }

            $applicationNames[] = $worker['applicationName'];
        }

        if (count($applicationNames) !== count(array_unique($applicationNames))) {
            throw new RuntimeException('The PostgreSQL lock witness batch has duplicate application names.');
        }

        $placeholders = implode(',', array_fill(0, count($applicationNames), '?'));
        $deadline = microtime(true) + self::LOCK_WAIT_TIMEOUT_SECONDS;

        while (microtime(true) < $deadline) {
            foreach ($workerNames as $workerName) {
                $worker = $this->workers[$workerName] ?? null;

                if (! is_array($worker) || ! $worker['process']->isRunning()) {
                    throw new RuntimeException('A PostgreSQL concurrency worker exited before its lock witness.');
                }
            }

            DB::connection('pgsql')->select('select pg_stat_clear_snapshot()');
            $activities = DB::connection('pgsql')->select(
                'select activity.pid, activity.application_name, activity.state,
                    activity.wait_event_type, activity.wait_event, activity.query,
                    array_to_json(pg_blocking_pids(activity.pid))::text as blocking_pids_json
                from pg_stat_activity as activity
                where activity.application_name in ('.$placeholders.')',
                $applicationNames,
            );

            $activitiesByApplicationName = [];
            $activitiesByPid = [];
            $validSnapshot = true;

            foreach ($activities as $activity) {
                if (isset($activitiesByApplicationName[$activity->application_name])) {
                    $validSnapshot = false;

                    break;
                }

                $blockingPids = json_decode($activity->blocking_pids_json, true);

                if (! is_array($blockingPids) || ! array_is_list($blockingPids)) {
                    $validSnapshot = false;

                    break;
                }

                foreach ($blockingPids as $blockingPid) {
                    if (! is_int($blockingPid) || $blockingPid <= 0) {
                        $validSnapshot = false;

                        break 2;
                    }
                }

                $activityDetails = [
                    'pid' => (int) $activity->pid,
                    'applicationName' => $activity->application_name,
                    'state' => $activity->state,
                    'waitEventType' => $activity->wait_event_type,
                    'waitEvent' => $activity->wait_event,
                    'query' => $activity->query,
                    'blockingPids' => $blockingPids,
                ];

                $activitiesByApplicationName[$activity->application_name] = $activityDetails;
                $activitiesByPid[$activityDetails['pid']] = $activityDetails;
            }

            if (
                ! $validSnapshot
                || count($activitiesByApplicationName) !== count($workerNames)
            ) {
                usleep(20_000);

                continue;
            }

            $batchWorkerPids = array_fill_keys(array_column($activitiesByPid, 'pid'), true);
            $witnesses = [];
            $validWitnessBatch = true;

            foreach ($workerNames as $workerName) {
                $applicationName = $this->workers[$workerName]['applicationName'];
                $activity = $activitiesByApplicationName[$applicationName] ?? null;

                if (
                    ! is_array($activity)
                    || $activity['state'] !== 'active'
                    || $activity['waitEventType'] !== 'Lock'
                    || ! is_string($activity['waitEvent'])
                    || $activity['waitEvent'] === ''
                    || ! $this->queryWaitsOnExpectedTable($activity['query'], $expectedTable)
                ) {
                    $validWitnessBatch = false;

                    break;
                }

                if ($expectedTable === 'users') {
                    if (
                        $activity['waitEvent'] !== 'transactionid'
                        || ! in_array($this->parentBackendPid, $activity['blockingPids'], true)
                    ) {
                        $validWitnessBatch = false;

                        break;
                    }

                    $blockingPaths = [[$activity['pid'], $this->parentBackendPid]];
                } else {
                    $blockingPaths = $this->blockingPathsToParent(
                        $activity['pid'],
                        [],
                        $activitiesByPid,
                        $batchWorkerPids,
                        $expectedTable,
                    );

                    if ($blockingPaths === null) {
                        $validWitnessBatch = false;

                        break;
                    }
                }

                $witnesses[$workerName] = [
                    'pid' => $activity['pid'],
                    'parentPid' => $this->parentBackendPid,
                    'applicationName' => $activity['applicationName'],
                    'expectedTable' => $expectedTable,
                    'waitEvent' => $activity['waitEvent'],
                    'blockingPids' => $activity['blockingPids'],
                    'blockingPaths' => $blockingPaths,
                ];
            }

            if ($validWitnessBatch && count($witnesses) === count($workerNames)) {
                $this->lockWitnesses = $witnesses;

                return $witnesses;
            }

            usleep(20_000);
        }

        throw new RuntimeException('The expected PostgreSQL row-lock witnesses were not observed before the deadline.');
    }

    /**
     * @param  list<int>  $path
     * @param  array<int, array{
     *     pid: int,
     *     applicationName: string,
     *     state: string,
     *     waitEventType: ?string,
     *     waitEvent: ?string,
     *     query: ?string,
     *     blockingPids: list<int>
     * }>  $activitiesByPid
     * @param  array<int, bool>  $batchWorkerPids
     * @return list<list<int>>|null
     */
    private function blockingPathsToParent(
        int $pid,
        array $path,
        array $activitiesByPid,
        array $batchWorkerPids,
        string $expectedTable,
    ): ?array {
        if ($pid === $this->parentBackendPid) {
            $path[] = $pid;

            return [$path];
        }

        if (
            in_array($pid, $path, true)
            || count($path) >= count($batchWorkerPids) + 1
            || ! isset($batchWorkerPids[$pid], $activitiesByPid[$pid])
        ) {
            return null;
        }

        $activity = $activitiesByPid[$pid];

        if (
            $activity['state'] !== 'active'
            || $activity['waitEventType'] !== 'Lock'
            || ! $this->queryWaitsOnExpectedTable($activity['query'], $expectedTable)
            || $activity['blockingPids'] === []
        ) {
            return null;
        }

        $path[] = $pid;
        $paths = [];

        foreach ($activity['blockingPids'] as $blockingPid) {
            $branchPaths = $this->blockingPathsToParent(
                $blockingPid,
                $path,
                $activitiesByPid,
                $batchWorkerPids,
                $expectedTable,
            );

            if ($branchPaths === null) {
                return null;
            }

            array_push($paths, ...$branchPaths);
        }

        return $paths;
    }

    /**
     * @param  array<string, array{
     *     pid: int,
     *     parentPid: int,
     *     applicationName: string,
     *     expectedTable: string,
     *     waitEvent: string,
     *     blockingPids: list<int>,
     *     blockingPaths: list<list<int>>
     * }>  $witnesses
     */
    private function assertDistinctLockWitnesses(array $witnesses): void
    {
        $this->assertNotEmpty($witnesses);
        $pids = array_column($witnesses, 'pid');
        $applicationNames = array_column($witnesses, 'applicationName');

        $this->assertCount(count($witnesses), array_unique($pids));
        $this->assertCount(count($witnesses), array_unique($applicationNames));

        foreach ($witnesses as $witness) {
            $this->assertGreaterThan(0, $witness['pid']);
            $this->assertSame($this->parentBackendPid, $witness['parentPid']);
            $this->assertContains($witness['expectedTable'], ['monitors', 'users']);
            $this->assertNotSame('', $witness['waitEvent']);
            $this->assertNotEmpty($witness['blockingPaths']);

            if ($witness['expectedTable'] === 'users') {
                $this->assertSame('transactionid', $witness['waitEvent']);
                $this->assertContains($witness['parentPid'], $witness['blockingPids']);
                $this->assertSame(
                    [[$witness['pid'], $witness['parentPid']]],
                    $witness['blockingPaths'],
                );
            }

            foreach ($witness['blockingPaths'] as $path) {
                $this->assertSame($witness['pid'], $path[0]);
                $this->assertSame($witness['parentPid'], $path[array_key_last($path)]);
                $this->assertLessThanOrEqual(count($witnesses) + 1, count($path));
                $this->assertCount(count($path), array_unique($path));

                foreach (array_slice($path, 1, -1) as $intermediatePid) {
                    $this->assertContains($intermediatePid, $pids);
                }
            }
        }
    }

    private function queryWaitsOnExpectedTable(?string $query, string $expectedTable): bool
    {
        if ($query === null) {
            return false;
        }

        $normalizedQuery = strtolower($query);

        if ($expectedTable === 'users') {
            return str_contains($normalizedQuery, 'insert into "users"')
                || str_contains($normalizedQuery, 'insert into users');
        }

        return str_contains($normalizedQuery, '"'.$expectedTable.'"')
            && str_contains($normalizedQuery, 'for update');
    }

    private function commitParentTransaction(): void
    {
        if (! $this->parentTransactionOpen) {
            throw new RuntimeException('The PostgreSQL lock barrier transaction is not open.');
        }

        DB::connection('pgsql')->commit();
        $this->parentTransactionOpen = false;
    }

    /**
     * @param  list<string>  $workerNames
     * @return array<string, array{status: int, response: array<string, mixed>}>
     */
    private function awaitWorkers(array $workerNames): array
    {
        $results = [];

        foreach ($workerNames as $workerName) {
            $worker = $this->workers[$workerName] ?? null;

            if (! is_array($worker)) {
                throw new RuntimeException('An access-pairing worker result was requested for an unknown worker.');
            }

            try {
                $worker['process']->wait();
            } catch (Throwable) {
                throw new RuntimeException('An access-pairing worker exceeded its finite process timeout.');
            }

            if (! $worker['process']->isSuccessful()) {
                throw new RuntimeException('An access-pairing worker failed without a sanitized result.');
            }

            $encodedResult = file_get_contents($worker['resultPath']);

            if (! is_string($encodedResult)) {
                throw new RuntimeException('An access-pairing worker did not produce its sanitized result.');
            }

            try {
                $result = json_decode($encodedResult, true, flags: JSON_THROW_ON_ERROR);
            } catch (Throwable) {
                throw new RuntimeException('An access-pairing worker result was not valid sanitized JSON.');
            }

            if (
                ! is_array($result)
                || ! is_int($result['status'] ?? null)
                || ! is_array($result['response'] ?? null)
                || $this->containsSensitiveResultKey($result)
            ) {
                throw new RuntimeException('An access-pairing worker result failed sanitization validation.');
            }

            $results[$workerName] = $result;
        }

        return $results;
    }

    private function containsSensitiveResultKey(mixed $value): bool
    {
        if (! is_array($value)) {
            return false;
        }

        foreach ($value as $key => $item) {
            if (
                is_string($key)
                && in_array(strtolower($key), ['accesstoken', 'invitationsecret'], true)
            ) {
                return true;
            }

            if ($this->containsSensitiveResultKey($item)) {
                return true;
            }
        }

        return false;
    }

    private function stopWorkers(): void
    {
        foreach ($this->workers as $worker) {
            $process = $worker['process'];

            if ($process->isRunning()) {
                $process->stop(1.0);
            }
        }
    }

    private function rollbackParentTransaction(): void
    {
        if (! $this->parentTransactionOpen) {
            return;
        }

        $connection = DB::connection('pgsql');

        while ($connection->transactionLevel() > $this->parentTransactionLevel) {
            $connection->rollBack();
        }

        if ($connection->transactionLevel() !== $this->parentTransactionLevel) {
            throw new RuntimeException('The PostgreSQL concurrency test transaction did not return to baseline.');
        }

        $this->parentTransactionOpen = false;
    }

    private function cleanupOwnedRecords(): void
    {
        $userIds = $this->ownedRecords['users'];

        foreach ($this->ownerIdentities as $identity) {
            $userId = User::query()
                ->where('firebase_project_id', $identity['projectId'])
                ->where('firebase_uid', $identity['firebaseUid'])
                ->value('id');

            if ($userId !== null && ! in_array($userId, $userIds, true)) {
                $userIds[] = $userId;
            }
        }

        $monitorIds = $this->ownedRecords['monitors'];

        if ($userIds !== []) {
            $monitorIds = array_merge(
                $monitorIds,
                Monitor::query()->whereIn('user_id', $userIds)->pluck('id')->all(),
            );
        }

        $invitationIds = $this->ownedRecords['invitations'];

        if ($monitorIds !== []) {
            $invitationIds = array_merge(
                $invitationIds,
                Invitation::query()
                    ->whereIn('monitor_id', array_values(array_unique($monitorIds)))
                    ->pluck('id')
                    ->all(),
            );
        }

        $invitationIds = array_values(array_unique($invitationIds));
        $requestIds = $this->ownedRecords['pairingRequests'];

        if ($invitationIds !== []) {
            $requestIds = array_merge(
                $requestIds,
                PairingRequest::query()
                    ->whereIn('invitation_id', $invitationIds)
                    ->pluck('id')
                    ->all(),
            );
        }

        $installationIds = $this->ownedRecords['installations'];

        if ($requestIds !== []) {
            $installationIds = array_merge(
                $installationIds,
                PairingRequest::query()
                    ->whereIn('id', $requestIds)
                    ->pluck('installation_id')
                    ->all(),
            );
        }

        $membershipIds = $this->ownedRecords['memberships'];

        if ($monitorIds !== []) {
            $monitorMemberships = MonitorMembership::query()
                ->whereIn('monitor_id', array_values(array_unique($monitorIds)))
                ->get(['id', 'installation_id']);
            $membershipIds = array_merge($membershipIds, $monitorMemberships->pluck('id')->all());
            $installationIds = array_merge($installationIds, $monitorMemberships->pluck('installation_id')->all());
        }

        $installationIds = array_values(array_unique($installationIds));
        $requestIds = array_values(array_unique($requestIds));
        $monitorIds = array_values(array_unique($monitorIds));
        $membershipIds = array_values(array_unique($membershipIds));
        $userIds = array_values(array_unique($userIds));

        $this->deleteOwnedRows('pairing_requests', 'id', $requestIds);
        $this->deleteOwnedRows('invitations', 'id', $invitationIds);
        $this->deleteOwnedRows('monitor_memberships', 'id', $membershipIds);

        if ($installationIds !== []) {
            PersonalAccessToken::query()
                ->where('tokenable_type', (new Installation)->getMorphClass())
                ->whereIn('tokenable_id', $installationIds)
                ->delete();
        }

        if ($this->ownedRecords['accessTokens'] !== []) {
            PersonalAccessToken::query()
                ->whereIn('id', $this->ownedRecords['accessTokens'])
                ->delete();
        }

        $this->deleteOwnedRows('installations', 'id', $installationIds);
        $this->deleteOwnedRows('monitors', 'id', $monitorIds);
        $this->deleteOwnedRows('users', 'id', $userIds);
    }

    /**
     * @param  list<int|string>  $ids
     */
    private function deleteOwnedRows(string $table, string $key, array $ids): void
    {
        if ($ids !== []) {
            DB::table($table)->whereIn($key, array_values(array_unique($ids)))->delete();
        }
    }

    private function cleanupWorkerArtifacts(): void
    {
        foreach ($this->workers as $worker) {
            foreach ([$worker['resultPath'], $worker['configCachePath']] as $path) {
                if (is_file($path) && ! unlink($path)) {
                    throw new RuntimeException('An access-pairing worker artifact could not be removed.');
                }
            }
        }

        if ($this->runDirectory !== null && is_dir($this->runDirectory)) {
            if (! rmdir($this->runDirectory)) {
                throw new RuntimeException('The access-pairing worker directory was not empty after cleanup.');
            }
        }
    }
}
