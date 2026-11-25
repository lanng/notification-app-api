<?php

namespace App\Support\SharedMonitor;

use App\Enums\AccessRole;
use App\Enums\FinancialEntryKind;
use App\Enums\SharedAlertSeverity;
use App\Models\InstallationPushToken;
use App\Models\Monitor;
use App\Models\MonitorHistoryEntry;
use App\Models\MonitorSnapshot;
use App\Support\AccessAndPairing\AccessAndPairing;
use App\Support\AccessAndPairing\AccessContext;
use App\Support\AccessAndPairing\AccessFailure;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Support\Facades\DB;

class SharedMonitorSync
{
    private const int MAX_STORED_HISTORY_ENTRIES = 500;

    public function __construct(
        private readonly AccessAndPairing $accessAndPairing,
        private readonly SharedAlertPushDispatcher $pushDispatcher,
    ) {}

    /**
     * @param  array{
     *     balanceCents: ?int,
     *     limitCents: int,
     *     repeatMinutes: int,
     *     pauseMinutes: int,
     *     needsReference: bool,
     *     alertCycleId: ?string,
     *     alertOpenedAtMs: ?int,
     *     alertEmissionCount: int,
     *     lastObservedAtMs: ?int,
     *     referenceConfirmedAtMs: ?int,
     *     entries: list<array{
     *         hostEntryId: int,
     *         kind: FinancialEntryKind,
     *         amountCents: int,
     *         balanceAfterCents: int,
     *         recordedAtMs: int
     *     }>
     * }  $payload
     * @return array<string, mixed>
     */
    public function publishHostSnapshot(
        AccessContext $context,
        string $requestedMonitorId,
        array $payload,
    ): array {
        $hostAccess = $this->accessAndPairing->preflightHostMonitor($context, $requestedMonitorId);

        /** @var array{
         *     snapshotData: array<string, mixed>,
         *     pushEvent: ?SharedAlertPushEvent,
         *     supportTokens: list<string>
         * } $outcome
         */
        $outcome = DB::transaction(function () use ($context, $hostAccess, $payload): array {
            $monitor = Monitor::query()
                ->whereKey($hostAccess['monitorId'])
                ->lockForUpdate()
                ->first();

            if (! $monitor instanceof Monitor) {
                throw new AccessFailure(404, 'resource_not_found', 'Recurso não encontrado.');
            }

            $this->accessAndPairing->assertCurrentActorTokenInTransaction($context);
            $this->accessAndPairing->assertCurrentHostMembershipInTransaction(
                $context,
                $monitor,
                $hostAccess['membershipId'],
            );

            $previous = MonitorSnapshot::query()
                ->where('monitor_id', $monitor->id)
                ->lockForUpdate()
                ->first();

            $previousState = $previous instanceof MonitorSnapshot
                ? [
                    'guestAlertActive' => $previous->guest_alert_active,
                    'severity' => $previous->severity,
                    'alertCycleId' => $previous->alert_cycle_id,
                    'alertEmissionCount' => $previous->alert_emission_count,
                ]
                : null;

            $now = now('UTC');
            $nowMs = (int) $now->getTimestampMs();
            $balanceCents = $payload['balanceCents'];
            $limitCents = $payload['limitCents'];
            $repeatMinutes = $payload['repeatMinutes'];
            $pauseMinutes = $payload['pauseMinutes'];
            $needsReference = $payload['needsReference'];
            $severity = SharedAlertSeverity::classify($balanceCents, $limitCents);

            $alertCycleId = $severity === SharedAlertSeverity::Attention || $severity === SharedAlertSeverity::Critical
                ? $payload['alertCycleId']
                : null;
            $alertOpenedAtMs = $severity === SharedAlertSeverity::Attention || $severity === SharedAlertSeverity::Critical
                ? ($payload['alertOpenedAtMs'] ?? $nowMs)
                : null;
            $alertEmissionCount = $severity === SharedAlertSeverity::Attention || $severity === SharedAlertSeverity::Critical
                ? max(0, $payload['alertEmissionCount'])
                : 0;

            [$guestAlertActive, $guestAlertEligibleAtMs] = $this->evaluateGuestAlert(
                severity: $severity,
                alertOpenedAtMs: $alertOpenedAtMs,
                alertEmissionCount: $alertEmissionCount,
                repeatMinutes: $repeatMinutes,
                nowMs: $nowMs,
            );

            $nextVersion = ($previous?->snapshot_version ?? 0) + 1;
            $decisionTime = $now->copy()->startOfSecond();

            $snapshot = $previous ?? new MonitorSnapshot(['monitor_id' => $monitor->id]);
            $snapshot->fill([
                'monitor_id' => $monitor->id,
                'host_installation_id' => $context->installationId,
                'host_generation' => $monitor->host_generation,
                'balance_cents' => $balanceCents,
                'limit_cents' => $limitCents,
                'repeat_minutes' => $repeatMinutes,
                'pause_minutes' => $pauseMinutes,
                'needs_reference' => $needsReference,
                'severity' => $severity,
                'alert_cycle_id' => $alertCycleId,
                'alert_opened_at_ms' => $alertOpenedAtMs,
                'alert_emission_count' => $alertEmissionCount,
                'guest_alert_active' => $guestAlertActive,
                'guest_alert_eligible_at_ms' => $guestAlertEligibleAtMs,
                'last_observed_at_ms' => $payload['lastObservedAtMs'],
                'reference_confirmed_at_ms' => $payload['referenceConfirmedAtMs'],
                'synced_at_ms' => $nowMs,
                'snapshot_version' => $nextVersion,
            ]);
            if (! $snapshot->exists) {
                $snapshot->created_at = $decisionTime;
            }
            $snapshot->updated_at = $decisionTime;
            $snapshot->save();

            if ($payload['entries'] !== []) {
                $rows = [];
                foreach ($payload['entries'] as $entry) {
                    $rows[] = [
                        'monitor_id' => $monitor->id,
                        'host_entry_id' => $entry['hostEntryId'],
                        'kind' => $entry['kind']->value,
                        'amount_cents' => $entry['amountCents'],
                        'balance_after_cents' => $entry['balanceAfterCents'],
                        'recorded_at_ms' => $entry['recordedAtMs'],
                        'created_at' => $decisionTime,
                        'updated_at' => $decisionTime,
                    ];
                }

                MonitorHistoryEntry::query()->upsert(
                    $rows,
                    ['monitor_id', 'host_entry_id'],
                    ['kind', 'amount_cents', 'balance_after_cents', 'recorded_at_ms', 'updated_at'],
                );

                $this->pruneHistoryEntries($monitor->id);
            }

            $pushEvent = $this->resolvePushEvent(
                monitorId: $monitor->id,
                previous: $previousState,
                current: $snapshot,
            );

            $supportTokens = [];
            if ($pushEvent !== null) {
                $supportTokens = InstallationPushToken::query()
                    ->whereIn(
                        'installation_id',
                        $monitor->memberships()
                            ->where('role', AccessRole::Support->value)
                            ->whereNotNull('approved_at')
                            ->whereNull('revoked_at')
                            ->select('installation_id'),
                    )
                    ->pluck('fcm_token')
                    ->filter(static fn (mixed $token): bool => is_string($token) && $token !== '')
                    ->values()
                    ->all();
            }

            return [
                'snapshotData' => $this->formatSnapshot($snapshot, $nowMs),
                'pushEvent' => $pushEvent,
                'supportTokens' => $supportTokens,
            ];
        }, attempts: 1);

        if ($outcome['pushEvent'] !== null && $outcome['supportTokens'] !== []) {
            $invalidTokens = $this->pushDispatcher->dispatchToTokens(
                $outcome['supportTokens'],
                $outcome['pushEvent'],
            );

            if ($invalidTokens !== []) {
                InstallationPushToken::query()
                    ->whereIn('fcm_token', $invalidTokens)
                    ->delete();
            }
        }

        return $outcome['snapshotData'];
    }

    /**
     * @return ?array<string, mixed>
     */
    public function showMonitorSnapshot(AccessContext $context, string $requestedMonitorId): ?array
    {
        $participant = $this->accessAndPairing->preflightMonitorParticipant($context, $requestedMonitorId);
        $snapshot = MonitorSnapshot::query()
            ->where('monitor_id', $participant['monitorId'])
            ->first();

        if (! $snapshot instanceof MonitorSnapshot) {
            return null;
        }

        $nowMs = (int) now('UTC')->getTimestampMs();

        return $this->formatSnapshot($snapshot, $nowMs);
    }

    /**
     * @return array{
     *     entries: list<array{
     *         hostEntryId: int,
     *         kind: string,
     *         amountCents: int,
     *         balanceAfterCents: int,
     *         recordedAtMs: int
     *     }>,
     *     hasMore: bool,
     *     nextBeforeEntryId: ?int
     * }
     */
    public function listMonitorHistory(
        AccessContext $context,
        string $requestedMonitorId,
        ?int $beforeEntryId,
        int $limit,
        string $filter,
    ): array {
        $participant = $this->accessAndPairing->preflightMonitorParticipant($context, $requestedMonitorId);
        $clampedLimit = max(1, min(100, $limit));

        $query = MonitorHistoryEntry::query()
            ->where('monitor_id', $participant['monitorId']);

        $allowedKind = match ($filter) {
            'entries' => FinancialEntryKind::PixCredit,
            'exits' => FinancialEntryKind::TagDebit,
            'adjustments' => FinancialEntryKind::Reference,
            default => null,
        };

        if ($allowedKind !== null) {
            $query->where('kind', $allowedKind->value);
        }

        if ($beforeEntryId !== null) {
            $cursor = MonitorHistoryEntry::query()
                ->where('monitor_id', $participant['monitorId'])
                ->where('host_entry_id', $beforeEntryId)
                ->first(['host_entry_id', 'recorded_at_ms']);

            if (! $cursor instanceof MonitorHistoryEntry) {
                return [
                    'entries' => [],
                    'hasMore' => false,
                    'nextBeforeEntryId' => null,
                ];
            }

            $cursorRecordedAtMs = $cursor->recorded_at_ms;
            $cursorHostEntryId = $cursor->host_entry_id;

            $query->where(function (Builder $sub) use ($cursorRecordedAtMs, $cursorHostEntryId): void {
                $sub->where('recorded_at_ms', '<', $cursorRecordedAtMs)
                    ->orWhere(function (Builder $tie) use ($cursorRecordedAtMs, $cursorHostEntryId): void {
                        $tie->where('recorded_at_ms', '=', $cursorRecordedAtMs)
                            ->where('host_entry_id', '<', $cursorHostEntryId);
                    });
            });
        }

        $rows = $query
            ->orderByDesc('recorded_at_ms')
            ->orderByDesc('host_entry_id')
            ->limit($clampedLimit + 1)
            ->get(['host_entry_id', 'kind', 'amount_cents', 'balance_after_cents', 'recorded_at_ms']);

        $hasMore = $rows->count() > $clampedLimit;
        $page = $hasMore ? $rows->slice(0, $clampedLimit)->values() : $rows;
        $last = $page->last();

        return [
            'entries' => $page->map(static fn (MonitorHistoryEntry $entry): array => [
                'hostEntryId' => $entry->host_entry_id,
                'kind' => $entry->kind->value,
                'amountCents' => $entry->amount_cents,
                'balanceAfterCents' => $entry->balance_after_cents,
                'recordedAtMs' => $entry->recorded_at_ms,
            ])->all(),
            'hasMore' => $hasMore,
            'nextBeforeEntryId' => $hasMore && $last instanceof MonitorHistoryEntry
                ? $last->host_entry_id
                : null,
        ];
    }

    /**
     * @return array{installationId: string, updatedAtMs: int}
     */
    public function registerPushToken(AccessContext $context, string $fcmToken): array
    {
        $this->accessAndPairing->assertActiveInstallation($context);

        $now = now('UTC');
        $nowMs = (int) $now->getTimestampMs();
        $decisionTime = $now->copy()->startOfSecond();

        InstallationPushToken::query()->upsert(
            [[
                'installation_id' => $context->installationId,
                'fcm_token' => $fcmToken,
                'updated_at_ms' => $nowMs,
                'created_at' => $decisionTime,
                'updated_at' => $decisionTime,
            ]],
            ['installation_id'],
            ['fcm_token', 'updated_at_ms', 'updated_at'],
        );

        return [
            'installationId' => $context->installationId,
            'updatedAtMs' => $nowMs,
        ];
    }

    public function deletePushToken(AccessContext $context): void
    {
        $this->accessAndPairing->assertActiveInstallation($context);

        InstallationPushToken::query()
            ->where('installation_id', $context->installationId)
            ->delete();
    }

    /**
     * @return array{0: bool, 1: ?int}
     */
    private function evaluateGuestAlert(
        SharedAlertSeverity $severity,
        ?int $alertOpenedAtMs,
        int $alertEmissionCount,
        int $repeatMinutes,
        int $nowMs,
    ): array {
        if ($severity === SharedAlertSeverity::Critical) {
            return [true, $alertOpenedAtMs ?? $nowMs];
        }

        if ($severity === SharedAlertSeverity::Attention) {
            $repeatMs = $repeatMinutes * 60_000;
            $baseOpenedAtMs = $alertOpenedAtMs ?? $nowMs;
            $eligibleAtMs = $baseOpenedAtMs + $repeatMs;
            $active = $alertEmissionCount >= 2 || $nowMs >= $eligibleAtMs;

            return [$active, $eligibleAtMs];
        }

        return [false, null];
    }

    /**
     * @param  null|array{
     *     guestAlertActive: bool,
     *     severity: SharedAlertSeverity,
     *     alertCycleId: ?string,
     *     alertEmissionCount: int
     * }  $previous
     */
    private function resolvePushEvent(
        string $monitorId,
        ?array $previous,
        MonitorSnapshot $current,
    ): ?SharedAlertPushEvent {
        $wasActive = $previous !== null && $previous['guestAlertActive'];
        $isActive = $current->guest_alert_active;
        $previousSeverity = $previous['severity'] ?? null;
        $currentSeverity = $current->severity;

        $eventType = null;

        if ($isActive) {
            if (! $wasActive) {
                $eventType = $currentSeverity === SharedAlertSeverity::Critical
                    ? 'alert_escalated'
                    : 'alert_triggered';
            } elseif (
                $previousSeverity !== SharedAlertSeverity::Critical
                && $currentSeverity === SharedAlertSeverity::Critical
            ) {
                $eventType = 'alert_escalated';
            } elseif (
                $current->alert_cycle_id !== ($previous['alertCycleId'] ?? null)
                || $current->alert_emission_count > ($previous['alertEmissionCount'] ?? 0)
            ) {
                $eventType = 'alert_repeated';
            }
        } elseif ($wasActive) {
            $eventType = 'alert_cleared';
        }

        if ($eventType === null) {
            return null;
        }

        return new SharedAlertPushEvent(
            eventType: $eventType,
            monitorId: $monitorId,
            severity: $currentSeverity,
            alertCycleId: $current->alert_cycle_id,
            alertEmissionCount: $current->alert_emission_count,
            guestAlertActive: $isActive,
            balanceCents: $current->balance_cents,
            limitCents: $current->limit_cents,
            repeatMinutes: $current->repeat_minutes,
            syncedAtMs: $current->synced_at_ms,
        );
    }

    /**
     * @return array<string, mixed>
     */
    private function formatSnapshot(MonitorSnapshot $snapshot, int $nowMs): array
    {
        $guestAlertActive = $snapshot->guest_alert_active;

        if (
            ! $guestAlertActive
            && $snapshot->severity === SharedAlertSeverity::Attention
            && $snapshot->guest_alert_eligible_at_ms !== null
            && $nowMs >= $snapshot->guest_alert_eligible_at_ms
        ) {
            $guestAlertActive = true;
        }

        return [
            'monitorId' => $snapshot->monitor_id,
            'hostGeneration' => (string) $snapshot->host_generation,
            'balanceCents' => $snapshot->balance_cents,
            'limitCents' => $snapshot->limit_cents,
            'repeatMinutes' => $snapshot->repeat_minutes,
            'pauseMinutes' => $snapshot->pause_minutes,
            'needsReference' => $snapshot->needs_reference,
            'severity' => $snapshot->severity->value,
            'alertCycleId' => $snapshot->alert_cycle_id,
            'alertOpenedAtMs' => $snapshot->alert_opened_at_ms,
            'alertEmissionCount' => $snapshot->alert_emission_count,
            'guestAlertActive' => $guestAlertActive,
            'guestAlertEligibleAtMs' => $snapshot->guest_alert_eligible_at_ms,
            'lastObservedAtMs' => $snapshot->last_observed_at_ms,
            'referenceConfirmedAtMs' => $snapshot->reference_confirmed_at_ms,
            'syncedAtMs' => $snapshot->synced_at_ms,
            'snapshotVersion' => $snapshot->snapshot_version,
            'serverTimeMs' => $nowMs,
        ];
    }

    private function pruneHistoryEntries(string $monitorId): void
    {
        $cutoff = MonitorHistoryEntry::query()
            ->where('monitor_id', $monitorId)
            ->orderByDesc('recorded_at_ms')
            ->orderByDesc('host_entry_id')
            ->offset(self::MAX_STORED_HISTORY_ENTRIES)
            ->limit(1)
            ->first(['recorded_at_ms', 'host_entry_id']);

        if (! $cutoff instanceof MonitorHistoryEntry) {
            return;
        }

        $cutoffRecordedAtMs = $cutoff->recorded_at_ms;
        $cutoffHostEntryId = $cutoff->host_entry_id;

        MonitorHistoryEntry::query()
            ->where('monitor_id', $monitorId)
            ->where(function (Builder $query) use ($cutoffRecordedAtMs, $cutoffHostEntryId): void {
                $query->where('recorded_at_ms', '<', $cutoffRecordedAtMs)
                    ->orWhere(function (Builder $tie) use ($cutoffRecordedAtMs, $cutoffHostEntryId): void {
                        $tie->where('recorded_at_ms', '=', $cutoffRecordedAtMs)
                            ->where('host_entry_id', '<=', $cutoffHostEntryId);
                    });
            })
            ->delete();
    }
}
