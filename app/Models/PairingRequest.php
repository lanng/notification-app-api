<?php

namespace App\Models;

use App\Enums\PairingRequestStatus;
use Database\Factories\PairingRequestFactory;
use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class PairingRequest extends Model
{
    /** @use HasFactory<PairingRequestFactory> */
    use HasFactory, HasUuids;

    protected $fillable = [
        'monitor_id',
        'invitation_id',
        'installation_id',
        'status',
        'request_expires_at',
        'decided_at',
        'decision_actor_membership_id',
    ];

    /**
     * Get the monitor for this request.
     *
     * @return BelongsTo<Monitor, $this>
     */
    public function monitor(): BelongsTo
    {
        return $this->belongsTo(Monitor::class);
    }

    /**
     * Get the invitation used for this request.
     *
     * @return BelongsTo<Invitation, $this>
     */
    public function invitation(): BelongsTo
    {
        return $this->belongsTo(Invitation::class);
    }

    /**
     * Get the installation requesting access.
     *
     * @return BelongsTo<Installation, $this>
     */
    public function installation(): BelongsTo
    {
        return $this->belongsTo(Installation::class);
    }

    /**
     * Get the membership that decided this request.
     *
     * @return BelongsTo<MonitorMembership, $this>
     */
    public function decisionActorMembership(): BelongsTo
    {
        return $this->belongsTo(MonitorMembership::class, 'decision_actor_membership_id');
    }

    /**
     * Get the attributes that should be cast.
     *
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'status' => PairingRequestStatus::class,
            'request_expires_at' => 'immutable_datetime',
            'decided_at' => 'immutable_datetime',
            'created_at' => 'immutable_datetime',
            'updated_at' => 'immutable_datetime',
        ];
    }
}
