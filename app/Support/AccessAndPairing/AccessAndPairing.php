<?php

namespace App\Support\AccessAndPairing;

use App\Enums\AccessRole;
use App\Enums\PairingRequestStatus;
use App\Models\Installation;
use App\Models\Invitation;
use App\Models\Monitor;
use App\Models\MonitorMembership;
use App\Models\PairingRequest;
use App\Models\User;
use App\Support\ApiV1\JsonTypes;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use Laravel\Sanctum\PersonalAccessToken;
use LogicException;

class AccessAndPairing
{
    /**
     * @return array{
     *     monitor: null|array{id: string},
     *     generation: string,
     *     host: null|array{installationId: string, label: ?string},
     *     requiresReference: true
     * }
     */
    public function discoverOwnerMonitor(VerifiedOwnerIdentity $identity): array
    {
        $this->assertConfiguredOwner($identity);

        $user = User::query()
            ->where('firebase_project_id', $identity->firebaseProjectId)
            ->where('firebase_uid', $identity->firebaseUid)
            ->first();

        if ($user === null) {
            return [
                'monitor' => null,
                'generation' => '0',
                'host' => null,
                'requiresReference' => true,
            ];
        }

        $monitor = $user->monitor()->first();

        if (! $monitor instanceof Monitor) {
            return [
                'monitor' => null,
                'generation' => '0',
                'host' => null,
                'requiresReference' => true,
            ];
        }

        $host = $monitor->memberships()
            ->where('role', AccessRole::Host)
            ->where('generation', $monitor->host_generation)
            ->whereNull('revoked_at')
            ->with('installation')
            ->first();

        return [
            'monitor' => ['id' => $monitor->id],
            'generation' => (string) $monitor->host_generation,
            'host' => $host instanceof MonitorMembership && $host->installation !== null
                ? [
                    'installationId' => $host->installation->id,
                    'label' => $host->installation->label,
                ]
                : null,
            'requiresReference' => true,
        ];
    }

    /**
     * @return array{
     *     installationId: string,
     *     monitorId: string,
     *     membershipId: string,
     *     role: 'Host'|'Support',
     *     status: 'Active',
     *     monitorGeneration: string
     * }
     */
    public function discoverCurrentInstallationAccess(string $installationId): array
    {
        $memberships = MonitorMembership::query()
            ->where('installation_id', $installationId)
            ->whereNull('revoked_at')
            ->whereNotNull('approved_at')
            ->whereIn('role', [AccessRole::Host->value, AccessRole::Support->value])
            ->with('monitor')
            ->get()
            ->filter(function (MonitorMembership $membership): bool {
                if (! $membership->monitor instanceof Monitor) {
                    return false;
                }

                return $membership->role !== AccessRole::Host
                    || $membership->generation === $membership->monitor->host_generation;
            });

        if ($memberships->count() !== 1) {
            throw new AccessFailure(403, 'access_forbidden', 'Acesso não permitido.');
        }

        /** @var MonitorMembership $membership */
        $membership = $memberships->first();
        $monitor = $membership->monitor;

        if (! $monitor instanceof Monitor) {
            throw new AccessFailure(403, 'access_forbidden', 'Acesso não permitido.');
        }

        return [
            'installationId' => $installationId,
            'monitorId' => $monitor->id,
            'membershipId' => $membership->id,
            'role' => $membership->role->value,
            'status' => 'Active',
            'monitorGeneration' => (string) $monitor->host_generation,
        ];
    }

    /**
     * @return array{monitorId: string, membershipId: string, generation: string}
     */
    public function preflightHostMonitor(AccessContext $context, string $requestedMonitorId): array
    {
        $this->assertCurrentActorToken($context, lockForUpdate: false);
        $access = $this->discoverCurrentInstallationAccess($context->installationId);

        if ($access['role'] !== AccessRole::Host->value) {
            throw new AccessFailure(403, 'access_forbidden', 'Acesso não permitido.');
        }

        if (strtolower($access['monitorId']) !== strtolower($requestedMonitorId)) {
            throw new AccessFailure(404, 'resource_not_found', 'Recurso não encontrado.');
        }

        return [
            'monitorId' => $access['monitorId'],
            'membershipId' => $access['membershipId'],
            'generation' => $access['monitorGeneration'],
        ];
    }

    public function authorizedHostMonitorId(AccessContext $context): string
    {
        $this->assertCurrentActorToken($context, lockForUpdate: false);
        $access = $this->discoverCurrentInstallationAccess($context->installationId);

        if ($access['role'] !== AccessRole::Host->value) {
            throw new AccessFailure(403, 'access_forbidden', 'Acesso não permitido.');
        }

        return $access['monitorId'];
    }

    /**
     * @return array{id: string, invitationSecret: string, createdAt: int, expiresAt: int}
     */
    public function issueInvitation(AccessContext $context, string $requestedMonitorId): array
    {
        $hostAccess = $this->preflightHostMonitor($context, $requestedMonitorId);

        return DB::transaction(function () use ($context, $hostAccess): array {
            $monitor = Monitor::query()
                ->whereKey($hostAccess['monitorId'])
                ->lockForUpdate()
                ->first();

            if (! $monitor instanceof Monitor) {
                throw new AccessFailure(404, 'resource_not_found', 'Recurso não encontrado.');
            }

            $this->assertCurrentActorToken($context);
            $this->assertCurrentHostMembership($context, $monitor, $hostAccess['membershipId']);

            $decisionTime = now('UTC')->startOfSecond();
            $expiresAt = $decisionTime->copy()->addMinutes(15);
            $secret = rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
            $invitation = $monitor->invitations()->create([
                'issuing_installation_id' => $context->installationId,
                'issuing_generation' => $monitor->host_generation,
                'secret_hash' => hash('sha256', $secret),
                'expires_at' => $expiresAt,
                'consumed_at' => null,
                'revoked_at' => null,
            ]);
            $invitation->created_at = $decisionTime;
            $invitation->updated_at = $decisionTime;
            $invitation->save();

            return [
                'id' => $invitation->id,
                'invitationSecret' => $secret,
                'createdAt' => $decisionTime->getTimestamp() * 1000,
                'expiresAt' => $expiresAt->getTimestamp() * 1000,
            ];
        }, attempts: 1);
    }

    /**
     * @return list<array{id: string, status: 'Available', createdAt: int, expiresAt: int}>
     */
    public function listInvitations(AccessContext $context, string $requestedMonitorId): array
    {
        $hostAccess = $this->preflightHostMonitor($context, $requestedMonitorId);
        $invitations = Invitation::query()
            ->where('monitor_id', $hostAccess['monitorId'])
            ->where('issuing_generation', (int) $hostAccess['generation'])
            ->whereNull('consumed_at')
            ->whereNull('revoked_at')
            ->where('expires_at', '>', now('UTC'))
            ->orderBy('created_at')
            ->orderBy('id')
            ->limit(50)
            ->get(['id', 'created_at', 'expires_at']);

        return $invitations
            ->map(fn (Invitation $invitation): array => [
                'id' => $invitation->id,
                'status' => 'Available',
                'createdAt' => $invitation->created_at->getTimestamp() * 1000,
                'expiresAt' => $invitation->expires_at->getTimestamp() * 1000,
            ])
            ->all();
    }

    /**
     * @return list<array{
     *     membershipId: string,
     *     installationId: string,
     *     label: ?string,
     *     role: 'Support',
     *     status: 'Active',
     *     approvedAt: int
     * }>
     */
    public function listSupportMemberships(AccessContext $context, string $requestedMonitorId): array
    {
        $hostAccess = $this->preflightHostMonitor($context, $requestedMonitorId);
        $memberships = MonitorMembership::query()
            ->where('monitor_id', $hostAccess['monitorId'])
            ->where('role', AccessRole::Support->value)
            ->whereNotNull('approved_at')
            ->whereNull('revoked_at')
            ->with('installation:id,label')
            ->orderBy('approved_at')
            ->orderBy('id')
            ->limit(3)
            ->get(['id', 'installation_id', 'approved_at']);

        return $memberships
            ->map(fn (MonitorMembership $membership): array => [
                'membershipId' => $membership->id,
                'installationId' => $membership->installation_id,
                'label' => $membership->installation?->label,
                'role' => AccessRole::Support->value,
                'status' => 'Active',
                'approvedAt' => $membership->approved_at->getTimestamp() * 1000,
            ])
            ->all();
    }

    /**
     * @return list<array{
     *     id: string,
     *     status: 'Pending',
     *     installation: array{id: string, label: ?string},
     *     createdAt: int,
     *     requestExpiresAt: int
     * }>
     */
    public function listPairingRequests(AccessContext $context, string $requestedMonitorId): array
    {
        $hostAccess = $this->preflightHostMonitor($context, $requestedMonitorId);
        $pairingRequests = PairingRequest::query()
            ->where('monitor_id', $hostAccess['monitorId'])
            ->where('status', PairingRequestStatus::Pending->value)
            ->where('request_expires_at', '>', now('UTC'))
            ->whereHas('invitation', function (Builder $query) use ($hostAccess): void {
                $query->where('issuing_generation', (int) $hostAccess['generation']);
            })
            ->with('installation:id,label')
            ->orderBy('created_at')
            ->orderBy('id')
            ->limit(50)
            ->get(['id', 'installation_id', 'status', 'created_at', 'request_expires_at']);

        return $pairingRequests
            ->map(fn (PairingRequest $pairingRequest): array => [
                'id' => $pairingRequest->id,
                'status' => PairingRequestStatus::Pending->value,
                'installation' => [
                    'id' => $pairingRequest->installation_id,
                    'label' => $pairingRequest->installation?->label,
                ],
                'createdAt' => $pairingRequest->created_at->getTimestamp() * 1000,
                'requestExpiresAt' => $pairingRequest->request_expires_at->getTimestamp() * 1000,
            ])
            ->all();
    }

    /**
     * @return array{
     *     requestId: string,
     *     status: 'Approved',
     *     membershipId: string,
     *     role: 'Support',
     *     decidedAt: int
     * }
     */
    public function approvePairingRequest(
        AccessContext $context,
        string $requestedMonitorId,
        string $pairingRequestId,
    ): array {
        $hostAccess = $this->preflightHostMonitor($context, $requestedMonitorId);

        if (! Str::isUuid($pairingRequestId)) {
            throw new AccessFailure(404, 'resource_not_found', 'Recurso não encontrado.');
        }

        $result = DB::transaction(function () use ($context, $hostAccess, $pairingRequestId): array|AccessFailure {
            $monitor = Monitor::query()
                ->whereKey($hostAccess['monitorId'])
                ->lockForUpdate()
                ->first();

            if (! $monitor instanceof Monitor) {
                throw new AccessFailure(404, 'resource_not_found', 'Recurso não encontrado.');
            }

            $this->assertCurrentActorToken($context);
            $this->assertCurrentHostMembership($context, $monitor, $hostAccess['membershipId']);

            $pairingRequest = PairingRequest::query()
                ->whereKey($pairingRequestId)
                ->where('monitor_id', $monitor->id)
                ->lockForUpdate()
                ->first();

            if (! $pairingRequest instanceof PairingRequest) {
                throw new AccessFailure(404, 'resource_not_found', 'Recurso não encontrado.');
            }

            if ($pairingRequest->status === PairingRequestStatus::Approved) {
                $supportMembership = MonitorMembership::query()
                    ->where('monitor_id', $monitor->id)
                    ->where('installation_id', $pairingRequest->installation_id)
                    ->where('role', AccessRole::Support->value)
                    ->whereNotNull('approved_at')
                    ->whereNull('revoked_at')
                    ->lockForUpdate()
                    ->first();

                if (
                    ! $supportMembership instanceof MonitorMembership
                    || $pairingRequest->decided_at === null
                ) {
                    throw new AccessFailure(
                        409,
                        'pairing_request_terminal',
                        'A solicitação de pareamento não pode mais ser alterada.',
                    );
                }

                return [
                    'requestId' => $pairingRequest->id,
                    'status' => PairingRequestStatus::Approved->value,
                    'membershipId' => $supportMembership->id,
                    'role' => AccessRole::Support->value,
                    'decidedAt' => $pairingRequest->decided_at->getTimestamp() * 1000,
                ];
            }

            if (
                $pairingRequest->status === PairingRequestStatus::Rejected
                || $pairingRequest->status === PairingRequestStatus::Cancelled
            ) {
                throw new AccessFailure(
                    409,
                    'pairing_request_terminal',
                    'A solicitação de pareamento não pode mais ser alterada.',
                );
            }

            if ($pairingRequest->status === PairingRequestStatus::Expired) {
                throw new AccessFailure(
                    410,
                    'pairing_request_unavailable',
                    'A solicitação de pareamento não está mais disponível.',
                );
            }

            $pendingToken = PersonalAccessToken::query()
                ->where('tokenable_type', (new Installation)->getMorphClass())
                ->where('tokenable_id', $pairingRequest->installation_id)
                ->where('name', 'pairing-pending')
                ->lockForUpdate()
                ->first();
            $decisionTime = now('UTC')->startOfSecond();

            if (! $pairingRequest->request_expires_at->isAfter($decisionTime)) {
                $pairingRequest->status = PairingRequestStatus::Expired;
                $pairingRequest->decided_at = $decisionTime;
                $pairingRequest->decision_actor_membership_id = null;
                $pairingRequest->updated_at = $decisionTime;
                $pairingRequest->save();

                return new AccessFailure(
                    410,
                    'pairing_request_unavailable',
                    'A solicitação de pareamento não está mais disponível.',
                );
            }

            $currentInvitationExists = Invitation::query()
                ->whereKey($pairingRequest->invitation_id)
                ->where('monitor_id', $monitor->id)
                ->where('issuing_generation', $monitor->host_generation)
                ->exists();

            if (! $currentInvitationExists) {
                throw new AccessFailure(
                    410,
                    'pairing_request_unavailable',
                    'A solicitação de pareamento não está mais disponível.',
                );
            }

            $activeSupportCount = MonitorMembership::query()
                ->where('monitor_id', $monitor->id)
                ->where('role', AccessRole::Support->value)
                ->whereNotNull('approved_at')
                ->whereNull('revoked_at')
                ->count();

            if ($activeSupportCount >= 3) {
                throw new AccessFailure(
                    409,
                    'support_limit_reached',
                    'O limite de dispositivos de suporte foi atingido.',
                );
            }

            if (
                ! $pendingToken instanceof PersonalAccessToken
                || $pendingToken->expires_at === null
                || ! $pendingToken->expires_at->isAfter($decisionTime)
            ) {
                throw new AccessFailure(
                    410,
                    'pairing_request_unavailable',
                    'A solicitação de pareamento não está mais disponível.',
                );
            }

            $supportMembership = MonitorMembership::query()->create([
                'monitor_id' => $monitor->id,
                'installation_id' => $pairingRequest->installation_id,
                'role' => AccessRole::Support,
                'generation' => null,
                'approved_at' => $decisionTime,
            ]);
            $supportMembership->created_at = $decisionTime;
            $supportMembership->updated_at = $decisionTime;
            $supportMembership->save();

            $pairingRequest->status = PairingRequestStatus::Approved;
            $pairingRequest->decided_at = $decisionTime;
            $pairingRequest->decision_actor_membership_id = $hostAccess['membershipId'];
            $pairingRequest->updated_at = $decisionTime;
            $pairingRequest->save();

            $pendingToken->expires_at = null;
            $pendingToken->updated_at = $decisionTime;
            $pendingToken->save();

            return [
                'requestId' => $pairingRequest->id,
                'status' => PairingRequestStatus::Approved->value,
                'membershipId' => $supportMembership->id,
                'role' => AccessRole::Support->value,
                'decidedAt' => $decisionTime->getTimestamp() * 1000,
            ];
        }, attempts: 1);

        if ($result instanceof AccessFailure) {
            throw $result;
        }

        return $result;
    }

    /**
     * @return array{requestId: string, status: 'Rejected', decidedAt: int}
     */
    public function rejectPairingRequest(
        AccessContext $context,
        string $requestedMonitorId,
        string $pairingRequestId,
    ): array {
        $hostAccess = $this->preflightHostMonitor($context, $requestedMonitorId);

        if (! Str::isUuid($pairingRequestId)) {
            throw new AccessFailure(404, 'resource_not_found', 'Recurso não encontrado.');
        }

        $result = DB::transaction(function () use ($context, $hostAccess, $pairingRequestId): array|AccessFailure {
            $monitor = Monitor::query()
                ->whereKey($hostAccess['monitorId'])
                ->lockForUpdate()
                ->first();

            if (! $monitor instanceof Monitor) {
                throw new AccessFailure(404, 'resource_not_found', 'Recurso não encontrado.');
            }

            $this->assertCurrentActorToken($context);
            $this->assertCurrentHostMembership($context, $monitor, $hostAccess['membershipId']);

            $pairingRequest = PairingRequest::query()
                ->whereKey($pairingRequestId)
                ->where('monitor_id', $monitor->id)
                ->lockForUpdate()
                ->first();

            if (! $pairingRequest instanceof PairingRequest) {
                throw new AccessFailure(404, 'resource_not_found', 'Recurso não encontrado.');
            }

            if ($pairingRequest->status === PairingRequestStatus::Rejected) {
                if ($pairingRequest->decided_at === null) {
                    throw new AccessFailure(
                        409,
                        'pairing_request_terminal',
                        'A solicitação de pareamento não pode mais ser alterada.',
                    );
                }

                return [
                    'requestId' => $pairingRequest->id,
                    'status' => PairingRequestStatus::Rejected->value,
                    'decidedAt' => $pairingRequest->decided_at->getTimestamp() * 1000,
                ];
            }

            if (
                $pairingRequest->status === PairingRequestStatus::Approved
                || $pairingRequest->status === PairingRequestStatus::Cancelled
            ) {
                throw new AccessFailure(
                    409,
                    'pairing_request_terminal',
                    'A solicitação de pareamento não pode mais ser alterada.',
                );
            }

            if ($pairingRequest->status === PairingRequestStatus::Expired) {
                throw new AccessFailure(
                    410,
                    'pairing_request_unavailable',
                    'A solicitação de pareamento não está mais disponível.',
                );
            }

            PersonalAccessToken::query()
                ->where('tokenable_type', (new Installation)->getMorphClass())
                ->where('tokenable_id', $pairingRequest->installation_id)
                ->lockForUpdate()
                ->get();
            $decisionTime = now('UTC')->startOfSecond();

            if (! $pairingRequest->request_expires_at->isAfter($decisionTime)) {
                $pairingRequest->status = PairingRequestStatus::Expired;
                $pairingRequest->decided_at = $decisionTime;
                $pairingRequest->decision_actor_membership_id = null;
                $pairingRequest->updated_at = $decisionTime;
                $pairingRequest->save();

                return new AccessFailure(
                    410,
                    'pairing_request_unavailable',
                    'A solicitação de pareamento não está mais disponível.',
                );
            }

            $pairingRequest->status = PairingRequestStatus::Rejected;
            $pairingRequest->decided_at = $decisionTime;
            $pairingRequest->decision_actor_membership_id = $hostAccess['membershipId'];
            $pairingRequest->updated_at = $decisionTime;
            $pairingRequest->save();

            PersonalAccessToken::query()
                ->where('tokenable_type', (new Installation)->getMorphClass())
                ->where('tokenable_id', $pairingRequest->installation_id)
                ->delete();

            return [
                'requestId' => $pairingRequest->id,
                'status' => PairingRequestStatus::Rejected->value,
                'decidedAt' => $decisionTime->getTimestamp() * 1000,
            ];
        }, attempts: 1);

        if ($result instanceof AccessFailure) {
            throw $result;
        }

        return $result;
    }

    public function revokeSupportMembership(
        AccessContext $context,
        string $requestedMonitorId,
        string $membershipId,
    ): void {
        $hostAccess = $this->preflightHostMonitor($context, $requestedMonitorId);

        if (! Str::isUuid($membershipId)) {
            throw new AccessFailure(404, 'resource_not_found', 'Recurso não encontrado.');
        }

        DB::transaction(function () use ($context, $hostAccess, $membershipId): void {
            $monitor = Monitor::query()
                ->whereKey($hostAccess['monitorId'])
                ->lockForUpdate()
                ->first();

            if (! $monitor instanceof Monitor) {
                throw new AccessFailure(404, 'resource_not_found', 'Recurso não encontrado.');
            }

            $this->assertCurrentActorToken($context);
            $this->assertCurrentHostMembership($context, $monitor, $hostAccess['membershipId']);

            $membership = MonitorMembership::query()
                ->whereKey($membershipId)
                ->where('monitor_id', $monitor->id)
                ->where('role', AccessRole::Support->value)
                ->lockForUpdate()
                ->first();

            if (! $membership instanceof MonitorMembership) {
                throw new AccessFailure(404, 'resource_not_found', 'Recurso não encontrado.');
            }

            if ($membership->revoked_at !== null) {
                return;
            }

            $decisionTime = now('UTC')->startOfSecond();
            $membership->revoked_at = $decisionTime;
            $membership->updated_at = $decisionTime;
            $membership->save();

            $tokenQuery = PersonalAccessToken::query()
                ->where('tokenable_type', (new Installation)->getMorphClass())
                ->where('tokenable_id', $membership->installation_id);
            $tokenQuery->lockForUpdate()->get();
            $tokenQuery->delete();
        }, attempts: 1);
    }

    public function cancelInvitation(
        AccessContext $context,
        string $requestedMonitorId,
        string $invitationId,
    ): void {
        $hostAccess = $this->preflightHostMonitor($context, $requestedMonitorId);

        if (! Str::isUuid($invitationId)) {
            throw new AccessFailure(404, 'resource_not_found', 'Recurso não encontrado.');
        }

        DB::transaction(function () use ($context, $hostAccess, $invitationId): void {
            $monitor = Monitor::query()
                ->whereKey($hostAccess['monitorId'])
                ->lockForUpdate()
                ->first();

            if (! $monitor instanceof Monitor) {
                throw new AccessFailure(404, 'resource_not_found', 'Recurso não encontrado.');
            }

            $this->assertCurrentActorToken($context);
            $this->assertCurrentHostMembership($context, $monitor, $hostAccess['membershipId']);

            $invitation = Invitation::query()
                ->whereKey($invitationId)
                ->where('monitor_id', $monitor->id)
                ->lockForUpdate()
                ->first();

            if (! $invitation instanceof Invitation) {
                throw new AccessFailure(404, 'resource_not_found', 'Recurso não encontrado.');
            }

            if ($invitation->consumed_at !== null) {
                throw new AccessFailure(409, 'invitation_already_consumed', 'O convite já foi utilizado.');
            }

            $decisionTime = now('UTC')->startOfSecond();

            if ($invitation->revoked_at === null && $invitation->expires_at->isAfter($decisionTime)) {
                $invitation->revoked_at = $decisionTime;
                $invitation->updated_at = $decisionTime;
                $invitation->save();
            }
        }, attempts: 1);
    }

    /**
     * @return array{
     *     requestId: string,
     *     installationId: string,
     *     status: 'Pending',
     *     requestExpiresAt: int,
     *     accessToken: string
     * }
     */
    public function redeemInvitation(string $invitationSecret, ?string $installationLabel): array
    {
        return DB::transaction(function () use ($invitationSecret, $installationLabel): array {
            $secretHash = hash('sha256', $invitationSecret);
            $monitorId = Invitation::query()
                ->where('secret_hash', $secretHash)
                ->value('monitor_id');

            if (! is_string($monitorId)) {
                throw new AccessFailure(410, 'invitation_unavailable', 'Convite indisponível.');
            }

            $monitor = Monitor::query()
                ->whereKey($monitorId)
                ->lockForUpdate()
                ->first();

            if (! $monitor instanceof Monitor) {
                throw new AccessFailure(410, 'invitation_unavailable', 'Convite indisponível.');
            }

            $invitation = Invitation::query()
                ->where('secret_hash', $secretHash)
                ->lockForUpdate()
                ->first();

            $redemptionTime = now('UTC');

            if (
                ! $invitation instanceof Invitation
                || $invitation->monitor_id !== $monitor->id
                || $invitation->consumed_at !== null
                || $invitation->revoked_at !== null
                || ! $invitation->expires_at->isAfter($redemptionTime)
                || $invitation->issuing_generation !== $monitor->host_generation
            ) {
                throw new AccessFailure(410, 'invitation_unavailable', 'Convite indisponível.');
            }

            $currentIssuerMembershipExists = MonitorMembership::query()
                ->where('monitor_id', $monitor->id)
                ->where('installation_id', $invitation->issuing_installation_id)
                ->where('role', AccessRole::Host->value)
                ->where('generation', $monitor->host_generation)
                ->whereNotNull('approved_at')
                ->whereNull('revoked_at')
                ->exists();

            if (! $currentIssuerMembershipExists) {
                throw new AccessFailure(410, 'invitation_unavailable', 'Convite indisponível.');
            }

            $decisionTime = $redemptionTime->copy()->startOfSecond();
            $requestExpiresAt = $decisionTime->copy()->addSeconds(900);

            $invitation->consumed_at = $decisionTime;
            $invitation->updated_at = $decisionTime;
            $invitation->save();

            $installation = Installation::query()->create([
                'label' => $installationLabel,
            ]);
            $installation->created_at = $decisionTime;
            $installation->updated_at = $decisionTime;
            $installation->save();

            $pairingRequest = PairingRequest::query()->create([
                'monitor_id' => $monitor->id,
                'invitation_id' => $invitation->id,
                'installation_id' => $installation->id,
                'status' => PairingRequestStatus::Pending,
                'request_expires_at' => $requestExpiresAt,
                'decided_at' => null,
                'decision_actor_membership_id' => null,
            ]);
            $pairingRequest->created_at = $decisionTime;
            $pairingRequest->updated_at = $decisionTime;
            $pairingRequest->save();

            $accessToken = $installation->createToken(
                'pairing-pending',
                ['pairing:pending'],
                $requestExpiresAt,
            );

            return [
                'requestId' => $pairingRequest->id,
                'installationId' => $installation->id,
                'status' => PairingRequestStatus::Pending->value,
                'requestExpiresAt' => $requestExpiresAt->getTimestamp() * 1000,
                'accessToken' => $accessToken->plainTextToken,
            ];
        }, attempts: 1);
    }

    /**
     * @return array{
     *     id: string,
     *     status: 'Pending'|'Approved'|'Rejected'|'Expired'|'Cancelled',
     *     requestExpiresAt: int,
     *     decidedAt: ?int,
     *     monitor: null|array{id: string, membershipId: string, role: 'Support'}
     * }
     */
    public function pollCurrentPairingRequest(AccessContext $context): array
    {
        $pairingRequest = PairingRequest::query()
            ->where('installation_id', $context->installationId)
            ->first();

        if (! $pairingRequest instanceof PairingRequest) {
            throw new AccessFailure(404, 'resource_not_found', 'Recurso não encontrado.');
        }

        if (
            $pairingRequest->status === PairingRequestStatus::Pending
            && ! $pairingRequest->request_expires_at->isAfter(now('UTC'))
        ) {
            throw new AccessFailure(
                410,
                'pairing_request_unavailable',
                'A solicitação de pareamento não está mais disponível.',
            );
        }

        $approvedSupport = null;
        $monitor = null;

        if ($pairingRequest->status === PairingRequestStatus::Approved) {
            $approvedSupport = MonitorMembership::query()
                ->where('monitor_id', $pairingRequest->monitor_id)
                ->where('installation_id', $context->installationId)
                ->where('role', AccessRole::Support->value)
                ->whereNotNull('approved_at')
                ->whereNull('revoked_at')
                ->first();

            if (! $approvedSupport instanceof MonitorMembership) {
                throw new AccessFailure(
                    410,
                    'pairing_request_unavailable',
                    'A solicitação de pareamento não está mais disponível.',
                );
            }

            $monitor = Monitor::query()->find($pairingRequest->monitor_id);

            if (! $monitor instanceof Monitor) {
                throw new AccessFailure(
                    410,
                    'pairing_request_unavailable',
                    'A solicitação de pareamento não está mais disponível.',
                );
            }
        }

        return [
            'id' => $pairingRequest->id,
            'status' => $pairingRequest->status->value,
            'requestExpiresAt' => $pairingRequest->request_expires_at->getTimestamp() * 1000,
            'decidedAt' => $pairingRequest->decided_at === null
                ? null
                : $pairingRequest->decided_at->getTimestamp() * 1000,
            'monitor' => $approvedSupport instanceof MonitorMembership && $monitor instanceof Monitor
                ? [
                    'id' => $monitor->id,
                    'membershipId' => $approvedSupport->id,
                    'role' => AccessRole::Support->value,
                ]
                : null,
        ];
    }

    /**
     * @return array{
     *     firstActivation: bool,
     *     data: array{
     *         monitorId: string,
     *         installationId: string,
     *         membershipId: string,
     *         role: 'Host',
     *         generation: string,
     *         requiresReference: true,
     *         accessToken: string,
     *         createdAt: int
     *     }
     * }
     */
    public function activateHost(
        VerifiedOwnerIdentity $identity,
        bool $confirmation,
        string $expectedGeneration,
    ): array {
        $this->assertConfiguredOwner($identity);
        $this->assertRecentAuthentication($identity->authTime);

        if (! $confirmation) {
            throw new AccessFailure(422, 'invalid_payload', 'Os dados enviados são inválidos.');
        }

        $expectedGeneration = JsonTypes::requireDecimalString(
            $expectedGeneration,
            'expectedGeneration',
            canonical: true,
        );
        $expectedGenerationValue = (int) $expectedGeneration;

        for ($attempt = 1; $attempt <= 3; $attempt++) {
            try {
                return DB::transaction(function () use (
                    $identity,
                    $expectedGenerationValue,
                ): array {
                    $user = User::query()
                        ->where('firebase_project_id', $identity->firebaseProjectId)
                        ->where('firebase_uid', $identity->firebaseUid)
                        ->first();

                    if ($user === null) {
                        $user = User::query()->create([
                            'firebase_project_id' => $identity->firebaseProjectId,
                            'firebase_uid' => $identity->firebaseUid,
                        ]);
                    }

                    $user = User::query()
                        ->whereKey($user->getKey())
                        ->lockForUpdate()
                        ->firstOrFail();
                    $monitor = $user->monitor()->lockForUpdate()->first();
                    $currentGeneration = $monitor?->host_generation ?? 0;
                    $firstActivation = $monitor === null;

                    if ($expectedGenerationValue !== $currentGeneration) {
                        throw new AccessFailure(
                            409,
                            'generation_conflict',
                            'A geração informada não corresponde ao estado atual.',
                        );
                    }

                    if (! $firstActivation && $currentGeneration === PHP_INT_MAX) {
                        throw new AccessFailure(
                            409,
                            'generation_conflict',
                            'A geração atual não pode ser incrementada.',
                        );
                    }

                    $nextGeneration = $firstActivation ? 1 : $currentGeneration + 1;
                    $decisionTime = now('UTC')->startOfSecond();

                    if ($monitor === null) {
                        $monitor = $user->monitor()->create([
                            'host_generation' => $nextGeneration,
                            'requires_reference' => true,
                        ]);
                        $monitor->created_at = $decisionTime;
                        $monitor->updated_at = $decisionTime;
                        $monitor->save();
                    } else {
                        $monitor->host_generation = $nextGeneration;
                        $monitor->requires_reference = true;
                        $monitor->updated_at = $decisionTime;
                        $monitor->save();

                        $this->revokeCurrentHost($monitor, $currentGeneration, $decisionTime);
                        $this->retirePreviousGeneration($monitor, $currentGeneration, $decisionTime);
                    }

                    $installation = Installation::query()->create(['label' => null]);
                    $installation->created_at = $decisionTime;
                    $installation->updated_at = $decisionTime;
                    $installation->save();

                    $newAccessToken = $installation->createToken(
                        'host-installation',
                        ['host:monitor'],
                        expiresAt: null,
                    );

                    $membership = $monitor->memberships()->create([
                        'installation_id' => $installation->id,
                        'role' => AccessRole::Host,
                        'generation' => $nextGeneration,
                        'approved_at' => $decisionTime,
                    ]);
                    $membership->created_at = $decisionTime;
                    $membership->updated_at = $decisionTime;
                    $membership->save();

                    return [
                        'firstActivation' => $firstActivation,
                        'data' => [
                            'monitorId' => $monitor->id,
                            'installationId' => $installation->id,
                            'membershipId' => $membership->id,
                            'role' => AccessRole::Host->value,
                            'generation' => (string) $nextGeneration,
                            'requiresReference' => true,
                            'accessToken' => $newAccessToken->plainTextToken,
                            'createdAt' => $decisionTime->getTimestamp() * 1000,
                        ],
                    ];
                }, attempts: 1);
            } catch (QueryException $exception) {
                if ($attempt === 3 || ! $this->isFirstRowRace($exception)) {
                    throw $exception;
                }
            }
        }

        throw new LogicException('Owner host activation retry loop ended unexpectedly.');
    }

    private function assertConfiguredOwner(VerifiedOwnerIdentity $identity): void
    {
        $firebaseProjectId = config('access_pairing.owner.firebase_project_id');
        $firebaseUid = config('access_pairing.owner.firebase_uid');

        if (
            ! is_string($firebaseProjectId)
            || $firebaseProjectId === ''
            || ! is_string($firebaseUid)
            || $firebaseUid === ''
            || $identity->provider !== 'google.com'
            || ! hash_equals($firebaseProjectId, $identity->firebaseProjectId)
            || ! hash_equals($firebaseUid, $identity->firebaseUid)
        ) {
            throw new AccessFailure(
                403,
                'owner_not_authorized',
                'Esta identidade não está autorizada como proprietária.',
            );
        }
    }

    private function assertRecentAuthentication(int $authTime): void
    {
        $currentTime = now('UTC')->getTimestamp();

        if ($authTime < $currentTime - 300 || $authTime > $currentTime) {
            throw new AccessFailure(
                403,
                'recent_authentication_required',
                'É necessária uma autenticação recente para ativar o dispositivo.',
            );
        }
    }

    private function assertCurrentActorToken(AccessContext $context, bool $lockForUpdate = true): void
    {
        $tokenQuery = PersonalAccessToken::query()->whereKey($context->accessTokenId);

        if ($lockForUpdate) {
            $tokenQuery->lockForUpdate();
        }

        $accessToken = $tokenQuery->first();
        $expirationMinutes = config('sanctum.expiration');

        if (
            ! $accessToken instanceof PersonalAccessToken
            || $accessToken->tokenable_type !== (new Installation)->getMorphClass()
            || ! hash_equals($context->installationId, (string) $accessToken->tokenable_id)
            || ($accessToken->expires_at !== null && ! $accessToken->expires_at->isAfter(now('UTC')))
            || (
                $expirationMinutes !== null
                && (
                    $accessToken->created_at === null
                    || ! $accessToken->created_at->isAfter(now('UTC')->subMinutes((int) $expirationMinutes))
                )
            )
        ) {
            throw new AccessFailure(401, 'access_unauthenticated', 'A credencial não é válida.');
        }
    }

    private function assertCurrentHostMembership(
        AccessContext $context,
        Monitor $monitor,
        string $membershipId,
    ): void {
        $membershipExists = MonitorMembership::query()
            ->whereKey($membershipId)
            ->where('monitor_id', $monitor->id)
            ->where('installation_id', $context->installationId)
            ->where('role', AccessRole::Host->value)
            ->where('generation', $monitor->host_generation)
            ->whereNotNull('approved_at')
            ->whereNull('revoked_at')
            ->lockForUpdate()
            ->exists();

        if (! $membershipExists) {
            throw new AccessFailure(403, 'access_forbidden', 'Acesso não permitido.');
        }
    }

    private function revokeCurrentHost(Monitor $monitor, int $generation, \DateTimeInterface $decisionTime): void
    {
        $currentHost = $monitor->memberships()
            ->where('role', AccessRole::Host->value)
            ->where('generation', $generation)
            ->whereNull('revoked_at')
            ->lockForUpdate()
            ->first();

        if ($currentHost === null) {
            return;
        }

        $currentHost->revoked_at = $decisionTime;
        $currentHost->save();
        $currentHost->installation?->tokens()->delete();
    }

    private function retirePreviousGeneration(
        Monitor $monitor,
        int $generation,
        \DateTimeInterface $decisionTime,
    ): void {
        $invitationIds = Invitation::query()
            ->where('monitor_id', $monitor->id)
            ->where('issuing_generation', $generation)
            ->lockForUpdate()
            ->pluck('id');

        if ($invitationIds->isEmpty()) {
            return;
        }

        Invitation::query()
            ->whereIn('id', $invitationIds)
            ->whereNull('revoked_at')
            ->whereNull('consumed_at')
            ->where('expires_at', '>', $decisionTime)
            ->update([
                'revoked_at' => $decisionTime,
                'updated_at' => $decisionTime,
            ]);

        $pendingRequests = PairingRequest::query()
            ->where('monitor_id', $monitor->id)
            ->whereIn('invitation_id', $invitationIds)
            ->where('status', PairingRequestStatus::Pending->value)
            ->lockForUpdate()
            ->get();

        foreach ($pendingRequests as $pendingRequest) {
            $pendingRequest->status = PairingRequestStatus::Cancelled;
            $pendingRequest->decided_at = $decisionTime;
            $pendingRequest->decision_actor_membership_id = null;
            $pendingRequest->save();

            $hasApprovedSupportMembership = MonitorMembership::query()
                ->where('monitor_id', $monitor->id)
                ->where('installation_id', $pendingRequest->installation_id)
                ->where('role', AccessRole::Support->value)
                ->whereNull('revoked_at')
                ->exists();

            if (! $hasApprovedSupportMembership) {
                Installation::query()
                    ->find($pendingRequest->installation_id)
                    ?->tokens()
                    ->delete();
            }
        }
    }

    private function isFirstRowRace(QueryException $exception): bool
    {
        if ((string) ($exception->errorInfo[0] ?? $exception->getCode()) !== '23505') {
            return false;
        }

        $message = $exception->getMessage();

        return str_contains($message, 'users_firebase_identity_unique')
            || str_contains($message, 'monitors_user_id_unique');
    }
}
