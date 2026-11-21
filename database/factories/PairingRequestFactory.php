<?php

namespace Database\Factories;

use App\Enums\PairingRequestStatus;
use App\Models\Installation;
use App\Models\Invitation;
use App\Models\PairingRequest;
use Illuminate\Database\Eloquent\Factories\Factory;

/**
 * @extends Factory<PairingRequest>
 */
class PairingRequestFactory extends Factory
{
    /**
     * Define the model's default state.
     *
     * @return array<string, mixed>
     */
    public function definition(): array
    {
        return [
            'invitation_id' => Invitation::factory(),
            'installation_id' => Installation::factory(),
            'status' => PairingRequestStatus::Pending,
            'request_expires_at' => now()->addMinutes(10),
            'decided_at' => null,
            'decision_actor_membership_id' => null,
        ];
    }

    public function configure(): static
    {
        return $this->afterMaking(function (PairingRequest $pairingRequest): void {
            $pairingRequest->monitor_id = Invitation::query()
                ->findOrFail($pairingRequest->invitation_id)
                ->monitor_id;
        });
    }

    public function pending(): static
    {
        return $this->state(fn (array $attributes): array => [
            'status' => PairingRequestStatus::Pending,
        ]);
    }
}
