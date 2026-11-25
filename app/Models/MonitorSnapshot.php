<?php

namespace App\Models;

use App\Enums\SharedAlertSeverity;
use Database\Factories\MonitorSnapshotFactory;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class MonitorSnapshot extends Model
{
    /** @use HasFactory<MonitorSnapshotFactory> */
    use HasFactory;

    protected $primaryKey = 'monitor_id';

    public $incrementing = false;

    protected $keyType = 'string';

    protected $fillable = [
        'monitor_id',
        'host_installation_id',
        'host_generation',
        'balance_cents',
        'limit_cents',
        'repeat_minutes',
        'pause_minutes',
        'needs_reference',
        'severity',
        'alert_cycle_id',
        'alert_opened_at_ms',
        'alert_emission_count',
        'guest_alert_active',
        'guest_alert_eligible_at_ms',
        'last_observed_at_ms',
        'reference_confirmed_at_ms',
        'synced_at_ms',
        'snapshot_version',
    ];

    /**
     * @return BelongsTo<Monitor, $this>
     */
    public function monitor(): BelongsTo
    {
        return $this->belongsTo(Monitor::class);
    }

    /**
     * @return BelongsTo<Installation, $this>
     */
    public function hostInstallation(): BelongsTo
    {
        return $this->belongsTo(Installation::class, 'host_installation_id');
    }

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'host_generation' => 'integer',
            'balance_cents' => 'integer',
            'limit_cents' => 'integer',
            'repeat_minutes' => 'integer',
            'pause_minutes' => 'integer',
            'needs_reference' => 'boolean',
            'severity' => SharedAlertSeverity::class,
            'alert_opened_at_ms' => 'integer',
            'alert_emission_count' => 'integer',
            'guest_alert_active' => 'boolean',
            'guest_alert_eligible_at_ms' => 'integer',
            'last_observed_at_ms' => 'integer',
            'reference_confirmed_at_ms' => 'integer',
            'synced_at_ms' => 'integer',
            'snapshot_version' => 'integer',
            'created_at' => 'immutable_datetime',
            'updated_at' => 'immutable_datetime',
        ];
    }
}
