<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class InstallationPushToken extends Model
{
    protected $primaryKey = 'installation_id';

    public $incrementing = false;

    protected $keyType = 'string';

    protected $fillable = [
        'installation_id',
        'fcm_token',
        'updated_at_ms',
    ];

    /**
     * @return BelongsTo<Installation, $this>
     */
    public function installation(): BelongsTo
    {
        return $this->belongsTo(Installation::class);
    }

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'updated_at_ms' => 'integer',
            'created_at' => 'immutable_datetime',
            'updated_at' => 'immutable_datetime',
        ];
    }
}
