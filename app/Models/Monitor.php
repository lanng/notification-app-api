<?php

namespace App\Models;

use Database\Factories\MonitorFactory;
use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Database\Eloquent\Relations\HasOne;

class Monitor extends Model
{
    /** @use HasFactory<MonitorFactory> */
    use HasFactory, HasUuids;

    protected $fillable = [
        'user_id',
        'host_generation',
        'requires_reference',
    ];

    /**
     * Get the external identity that owns this monitor.
     *
     * @return BelongsTo<User, $this>
     */
    public function user(): BelongsTo
    {
        return $this->belongsTo(User::class);
    }

    /**
     * Get memberships for this monitor.
     *
     * @return HasMany<MonitorMembership, $this>
     */
    public function memberships(): HasMany
    {
        return $this->hasMany(MonitorMembership::class);
    }

    /**
     * Get invitations for this monitor.
     *
     * @return HasMany<Invitation, $this>
     */
    public function invitations(): HasMany
    {
        return $this->hasMany(Invitation::class);
    }

    /**
     * Get pairing requests for this monitor.
     *
     * @return HasMany<PairingRequest, $this>
     */
    public function pairingRequests(): HasMany
    {
        return $this->hasMany(PairingRequest::class);
    }

    /**
     * Get the latest shared monitor snapshot.
     *
     * @return HasOne<MonitorSnapshot, $this>
     */
    public function snapshot(): HasOne
    {
        return $this->hasOne(MonitorSnapshot::class);
    }

    /**
     * Get sanitized shared history entries for this monitor.
     *
     * @return HasMany<MonitorHistoryEntry, $this>
     */
    public function historyEntries(): HasMany
    {
        return $this->hasMany(MonitorHistoryEntry::class);
    }

    /**
     * Get the attributes that should be cast.
     *
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'host_generation' => 'integer',
            'requires_reference' => 'boolean',
            'created_at' => 'immutable_datetime',
            'updated_at' => 'immutable_datetime',
        ];
    }
}
