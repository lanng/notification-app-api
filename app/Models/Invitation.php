<?php

namespace App\Models;

use Database\Factories\InvitationFactory;
use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\HasOne;

class Invitation extends Model
{
    /** @use HasFactory<InvitationFactory> */
    use HasFactory, HasUuids;

    protected $fillable = [
        'monitor_id',
        'issuing_installation_id',
        'issuing_generation',
        'secret_hash',
        'expires_at',
        'consumed_at',
        'revoked_at',
    ];

    protected $hidden = [
        'secret_hash',
    ];

    /**
     * Get the monitor for this invitation.
     *
     * @return BelongsTo<Monitor, $this>
     */
    public function monitor(): BelongsTo
    {
        return $this->belongsTo(Monitor::class);
    }

    /**
     * Get the installation that issued this invitation.
     *
     * @return BelongsTo<Installation, $this>
     */
    public function issuingInstallation(): BelongsTo
    {
        return $this->belongsTo(Installation::class, 'issuing_installation_id');
    }

    /**
     * Get the pairing request created from this invitation.
     *
     * @return HasOne<PairingRequest, $this>
     */
    public function pairingRequest(): HasOne
    {
        return $this->hasOne(PairingRequest::class);
    }

    /**
     * Get the attributes that should be cast.
     *
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'issuing_generation' => 'integer',
            'expires_at' => 'immutable_datetime',
            'consumed_at' => 'immutable_datetime',
            'revoked_at' => 'immutable_datetime',
            'created_at' => 'immutable_datetime',
            'updated_at' => 'immutable_datetime',
        ];
    }
}
