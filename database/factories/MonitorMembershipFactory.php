<?php

namespace Database\Factories;

use App\Enums\AccessRole;
use App\Models\Installation;
use App\Models\Monitor;
use App\Models\MonitorMembership;
use Illuminate\Database\Eloquent\Factories\Factory;

/**
 * @extends Factory<MonitorMembership>
 */
class MonitorMembershipFactory extends Factory
{
    /**
     * Define the model's default state.
     *
     * @return array<string, mixed>
     */
    public function definition(): array
    {
        return [
            'monitor_id' => Monitor::factory(),
            'installation_id' => Installation::factory(),
            'role' => AccessRole::Support,
            'generation' => null,
            'approved_at' => now(),
            'revoked_at' => null,
        ];
    }

    public function host(): static
    {
        return $this->state(fn (array $attributes): array => [
            'role' => AccessRole::Host,
            'generation' => 1,
        ]);
    }
}
