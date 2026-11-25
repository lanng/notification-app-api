<?php

namespace App\Models;

use Database\Factories\InstallationFactory;
use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Database\Eloquent\Relations\HasOne;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Laravel\Sanctum\HasApiTokens;
use Laravel\Sanctum\PersonalAccessToken;

class Installation extends Authenticatable
{
    /**
     * @use HasApiTokens<PersonalAccessToken>
     * @use HasFactory<InstallationFactory>
     */
    use HasApiTokens, HasFactory, HasUuids;

    protected $fillable = [
        'label',
    ];

    /**
     * Get memberships associated with this installation.
     *
     * @return HasMany<MonitorMembership, $this>
     */
    public function memberships(): HasMany
    {
        return $this->hasMany(MonitorMembership::class);
    }

    /**
     * Get invitations issued by this installation.
     *
     * @return HasMany<Invitation, $this>
     */
    public function issuedInvitations(): HasMany
    {
        return $this->hasMany(Invitation::class, 'issuing_installation_id');
    }

    /**
     * Get pairing requests made by this installation.
     *
     * @return HasMany<PairingRequest, $this>
     */
    public function pairingRequests(): HasMany
    {
        return $this->hasMany(PairingRequest::class);
    }

    /**
     * Get the push token registered for this installation.
     *
     * @return HasOne<InstallationPushToken, $this>
     */
    public function pushToken(): HasOne
    {
        return $this->hasOne(InstallationPushToken::class);
    }

    /**
     * Get the attributes that should be cast.
     *
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'created_at' => 'immutable_datetime',
            'updated_at' => 'immutable_datetime',
        ];
    }
}
