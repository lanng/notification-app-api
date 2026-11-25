<?php

namespace App\Support\SharedMonitor;

use App\Enums\SharedAlertSeverity;

final readonly class SharedAlertPushEvent
{
    public function __construct(
        public string $eventType,
        public string $monitorId,
        public SharedAlertSeverity $severity,
        public ?string $alertCycleId,
        public int $alertEmissionCount,
        public bool $guestAlertActive,
        public ?int $balanceCents,
        public int $limitCents,
        public int $repeatMinutes,
        public int $syncedAtMs,
    ) {}

    /**
     * @return array<string, string>
     */
    public function toFcmDataPayload(): array
    {
        return [
            'type' => $this->eventType,
            'monitorId' => $this->monitorId,
            'severity' => $this->severity->value,
            'alertCycleId' => $this->alertCycleId ?? '',
            'alertEmissionCount' => (string) $this->alertEmissionCount,
            'guestAlertActive' => $this->guestAlertActive ? 'true' : 'false',
            'balanceCents' => $this->balanceCents === null ? '' : (string) $this->balanceCents,
            'limitCents' => (string) $this->limitCents,
            'repeatMinutes' => (string) $this->repeatMinutes,
            'syncedAtMs' => (string) $this->syncedAtMs,
        ];
    }
}
