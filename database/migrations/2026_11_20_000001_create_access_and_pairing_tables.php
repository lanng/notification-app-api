<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('monitors', function (Blueprint $table) {
            $table->uuid('id')->primary();
            $table->foreignId('user_id')->constrained();
            $table->bigInteger('host_generation');
            $table->boolean('requires_reference')->default(true);
            $table->timestampsTz(0);
            $table->unique('user_id', 'monitors_user_id_unique');
        });

        Schema::create('installations', function (Blueprint $table) {
            $table->uuid('id')->primary();
            $table->string('label', 128)->nullable();
            $table->timestampsTz(0);
        });

        Schema::create('monitor_memberships', function (Blueprint $table) {
            $table->uuid('id')->primary();
            $table->foreignUuid('monitor_id')->constrained()->cascadeOnDelete();
            $table->foreignUuid('installation_id')->constrained()->cascadeOnDelete();
            $table->enum('role', ['Host', 'Support']);
            $table->bigInteger('generation')->nullable();
            $table->timestampTz('approved_at', 0);
            $table->timestampTz('revoked_at', 0)->nullable();
            $table->timestampsTz(0);
            $table->unique(
                ['monitor_id', 'installation_id'],
                'monitor_memberships_monitor_id_installation_id_unique',
            );
        });

        DB::statement(
            "CREATE UNIQUE INDEX monitor_memberships_one_active_host_unique ON monitor_memberships (monitor_id) WHERE \"role\" = 'Host' AND revoked_at IS NULL",
        );

        Schema::create('invitations', function (Blueprint $table) {
            $table->uuid('id')->primary();
            $table->foreignUuid('monitor_id')->constrained()->cascadeOnDelete();
            $table->foreignUuid('issuing_installation_id')->constrained('installations')->cascadeOnDelete();
            $table->bigInteger('issuing_generation');
            $table->string('secret_hash', 64)->unique();
            $table->timestampTz('expires_at', 0);
            $table->timestampTz('consumed_at', 0)->nullable();
            $table->timestampTz('revoked_at', 0)->nullable();
            $table->timestampsTz(0);
        });

        Schema::create('pairing_requests', function (Blueprint $table) {
            $table->uuid('id')->primary();
            $table->foreignUuid('monitor_id')->constrained()->cascadeOnDelete();
            $table->foreignUuid('invitation_id')->constrained()->cascadeOnDelete();
            $table->foreignUuid('installation_id')->constrained()->cascadeOnDelete();
            $table->enum('status', ['Pending', 'Approved', 'Rejected', 'Expired', 'Cancelled']);
            $table->timestampTz('request_expires_at', 0);
            $table->timestampTz('decided_at', 0)->nullable();
            $table->foreignUuid('decision_actor_membership_id')
                ->nullable()
                ->constrained('monitor_memberships')
                ->nullOnDelete();
            $table->timestampsTz(0);
            $table->unique('invitation_id', 'pairing_requests_invitation_id_unique');
            $table->unique('installation_id', 'pairing_requests_installation_id_unique');
        });
    }

    public function down(): void
    {
        foreach (['pairing_requests', 'invitations', 'monitor_memberships', 'installations', 'monitors'] as $table) {
            if (Schema::hasTable($table) && DB::table($table)->exists()) {
                throw new RuntimeException('Refusing to drop populated access and pairing tables.');
            }
        }

        DB::statement('DROP INDEX IF EXISTS monitor_memberships_one_active_host_unique');

        Schema::dropIfExists('pairing_requests');
        Schema::dropIfExists('invitations');
        Schema::dropIfExists('monitor_memberships');
        Schema::dropIfExists('installations');
        Schema::dropIfExists('monitors');
    }
};
