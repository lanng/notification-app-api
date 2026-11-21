<?php

namespace App\Models;

use App\Enums\AccessRole;
use Database\Factories\MonitorMembershipFactory;
use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\HasMany;

class MonitorMembership extends Model
{
    /** @use HasFactory<MonitorMembershipFactory> */
    use HasFactory, HasUuids;

    protected $fillable = [
        'monitor_id',
        'installation_id',
        'role',
        'generation',
        'approved_at',
        'revoked_at',
    ];

    /**
     * Get the monitor for this membership.
     *
     * @return BelongsTo<Monitor, $this>
     */
    public function monitor(): BelongsTo
    {
        return $this->belongsTo(Monitor::class);
    }

    /**
     * Get the installation for this membership.
     *
     * @return BelongsTo<Installation, $this>
     */
    public function installation(): BelongsTo
    {
        return $this->belongsTo(Installation::class);
    }

    /**
     * Get requests decided by this membership.
     *
     * @return HasMany<PairingRequest, $this>
     */
    public function decidedPairingRequests(): HasMany
    {
        return $this->hasMany(PairingRequest::class, 'decision_actor_membership_id');
    }

    /**
     * Get the attributes that should be cast.
     *
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'role' => AccessRole::class,
            'generation' => 'integer',
            'approved_at' => 'immutable_datetime',
            'revoked_at' => 'immutable_datetime',
            'created_at' => 'immutable_datetime',
            'updated_at' => 'immutable_datetime',
        ];
    }
}
