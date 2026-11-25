<?php

namespace Database\Factories;

use App\Enums\FinancialEntryKind;
use App\Models\Monitor;
use App\Models\MonitorHistoryEntry;
use Illuminate\Database\Eloquent\Factories\Factory;

/**
 * @extends Factory<MonitorHistoryEntry>
 */
class MonitorHistoryEntryFactory extends Factory
{
    /**
     * @return array<string, mixed>
     */
    public function definition(): array
    {
        return [
            'monitor_id' => Monitor::factory(),
            'host_entry_id' => fake()->unique()->numberBetween(1, 100_000),
            'kind' => FinancialEntryKind::TagDebit,
            'amount_cents' => -1_250,
            'balance_after_cents' => 28_750,
            'recorded_at_ms' => now('UTC')->getTimestamp() * 1000,
        ];
    }
}
