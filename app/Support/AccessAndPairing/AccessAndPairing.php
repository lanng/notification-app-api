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
use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\DB;
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
