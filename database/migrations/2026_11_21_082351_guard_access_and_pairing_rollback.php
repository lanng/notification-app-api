<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Registers a rollback preflight after the access schema has been applied.
     */
    public function up(): void {}

    /**
     * Reverse the migrations.
     */
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
        ] as $table) {
            if (Schema::hasTable($table) && DB::table($table)->exists()) {
                throw new RuntimeException(
                    'Refusing to roll back while owner or access data exists.',
                );
            }
        }
    }
};
