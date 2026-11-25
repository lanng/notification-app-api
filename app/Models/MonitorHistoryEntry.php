<?php

namespace App\Models;

use App\Enums\FinancialEntryKind;
use Database\Factories\MonitorHistoryEntryFactory;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class MonitorHistoryEntry extends Model
{
    /** @use HasFactory<MonitorHistoryEntryFactory> */
    use HasFactory;

    protected $fillable = [
        'monitor_id',
        'host_entry_id',
        'kind',
        'amount_cents',
        'balance_after_cents',
        'recorded_at_ms',
    ];

    /**
     * @return BelongsTo<Monitor, $this>
     */
    public function monitor(): BelongsTo
    {
        return $this->belongsTo(Monitor::class);
    }

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'host_entry_id' => 'integer',
            'kind' => FinancialEntryKind::class,
            'amount_cents' => 'integer',
            'balance_after_cents' => 'integer',
            'recorded_at_ms' => 'integer',
            'created_at' => 'immutable_datetime',
            'updated_at' => 'immutable_datetime',
        ];
    }
}
