<?php

namespace Database\Factories;

use App\Enums\SharedAlertSeverity;
use App\Models\Installation;
use App\Models\Monitor;
use App\Models\MonitorSnapshot;
use Illuminate\Database\Eloquent\Factories\Factory;

/**
 * @extends Factory<MonitorSnapshot>
 */
class MonitorSnapshotFactory extends Factory
{
    /**
     * @return array<string, mixed>
     */
    public function definition(): array
    {
        $nowMs = now('UTC')->getTimestamp() * 1000;

        return [
            'monitor_id' => Monitor::factory(),
            'host_installation_id' => Installation::factory(),
            'host_generation' => 1,
            'balance_cents' => 35_000,
            'limit_cents' => 30_000,
            'repeat_minutes' => 15,
            'pause_minutes' => 30,
            'needs_reference' => false,
            'severity' => SharedAlertSeverity::Normal,
            'alert_cycle_id' => null,
            'alert_opened_at_ms' => null,
            'alert_emission_count' => 0,
            'guest_alert_active' => false,
            'guest_alert_eligible_at_ms' => null,
            'last_observed_at_ms' => $nowMs,
            'reference_confirmed_at_ms' => $nowMs,
            'synced_at_ms' => $nowMs,
            'snapshot_version' => 1,
        ];
    }
}
