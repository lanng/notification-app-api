<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('monitor_snapshots', function (Blueprint $table) {
            $table->foreignUuid('monitor_id')
                ->primary()
                ->constrained()
                ->cascadeOnDelete();
            $table->foreignUuid('host_installation_id')
                ->constrained('installations')
                ->cascadeOnDelete();
            $table->bigInteger('host_generation');
            $table->bigInteger('balance_cents')->nullable();
            $table->bigInteger('limit_cents');
            $table->smallInteger('repeat_minutes');
            $table->smallInteger('pause_minutes');
            $table->boolean('needs_reference')->default(false);
            $table->string('severity', 16);
            $table->string('alert_cycle_id', 128)->nullable();
            $table->bigInteger('alert_opened_at_ms')->nullable();
            $table->integer('alert_emission_count')->default(0);
            $table->boolean('guest_alert_active')->default(false);
            $table->bigInteger('guest_alert_eligible_at_ms')->nullable();
            $table->bigInteger('last_observed_at_ms')->nullable();
            $table->bigInteger('reference_confirmed_at_ms')->nullable();
            $table->bigInteger('synced_at_ms');
            $table->bigInteger('snapshot_version')->default(1);
            $table->timestampsTz(0);
        });

        Schema::create('monitor_history_entries', function (Blueprint $table) {
            $table->id();
            $table->foreignUuid('monitor_id')
                ->constrained()
                ->cascadeOnDelete();
            $table->bigInteger('host_entry_id');
            $table->string('kind', 24);
            $table->bigInteger('amount_cents');
            $table->bigInteger('balance_after_cents');
            $table->bigInteger('recorded_at_ms');
            $table->timestampsTz(0);

            $table->unique(
                ['monitor_id', 'host_entry_id'],
                'monitor_history_entries_monitor_host_entry_unique',
            );
            $table->index(
                ['monitor_id', 'recorded_at_ms', 'host_entry_id'],
                'monitor_history_entries_monitor_timeline_index',
            );
        });

        Schema::create('installation_push_tokens', function (Blueprint $table) {
            $table->foreignUuid('installation_id')
                ->primary()
                ->constrained()
                ->cascadeOnDelete();
            $table->string('fcm_token', 512);
            $table->bigInteger('updated_at_ms');
            $table->timestampsTz(0);
        });
    }

    public function down(): void
    {
        foreach ([
            'users',
            'password_reset_tokens',
            'sessions',
            'monitors',
            'installations',
            'monitor_memberships',
            'invitations',
            'pairing_requests',
            'personal_access_tokens',
            'installation_push_tokens',
            'monitor_history_entries',
            'monitor_snapshots',
        ] as $table) {
            if (Schema::hasTable($table) && DB::table($table)->exists()) {
                throw new RuntimeException('Refusing to roll back while owner or access data exists.');
            }
        }

        Schema::dropIfExists('installation_push_tokens');
        Schema::dropIfExists('monitor_history_entries');
        Schema::dropIfExists('monitor_snapshots');
    }
};
