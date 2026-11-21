<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        Schema::create('users', function (Blueprint $table) {
            $table->id();
            $table->string('firebase_project_id');
            $table->string('firebase_uid');
            $table->unique(
                ['firebase_project_id', 'firebase_uid'],
                'users_firebase_identity_unique',
            );
            $table->timestampsTz(0);
        });

        Schema::create('password_reset_tokens', function (Blueprint $table) {
            $table->string('email')->primary();
            $table->string('token');
            $table->timestamp('created_at')->nullable();
        });

        Schema::create('sessions', function (Blueprint $table) {
            $table->string('id')->primary();
            $table->foreignId('user_id')->nullable()->index();
            $table->string('ip_address', 45)->nullable();
            $table->text('user_agent')->nullable();
            $table->longText('payload');
            $table->integer('last_activity')->index();
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        $populatedTables = [];

        foreach (['users', 'password_reset_tokens', 'sessions'] as $table) {
            if (Schema::hasTable($table) && DB::table($table)->exists()) {
                $populatedTables[] = $table;
            }
        }

        if ($populatedTables !== []) {
            throw new RuntimeException('Refusing to drop populated user-related tables.');
        }

        Schema::dropIfExists('users');
        Schema::dropIfExists('password_reset_tokens');
        Schema::dropIfExists('sessions');
    }
};
