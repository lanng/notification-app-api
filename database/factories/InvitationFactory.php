<?php

namespace Database\Factories;

use App\Models\Installation;
use App\Models\Invitation;
use App\Models\Monitor;
use Illuminate\Database\Eloquent\Factories\Factory;

/**
 * @extends Factory<Invitation>
 */
class InvitationFactory extends Factory
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
            'issuing_installation_id' => Installation::factory(),
            'issuing_generation' => 1,
            'secret_hash' => hash('sha256', fake()->unique()->uuid()),
            'expires_at' => now()->addHour(),
            'consumed_at' => null,
            'revoked_at' => null,
        ];
    }
}
