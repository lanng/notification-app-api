<?php

namespace Tests\Feature;

use App\Enums\AccessRole;
use App\Enums\PairingRequestStatus;
use App\Models\Installation;
use App\Models\Invitation;
use App\Models\Monitor;
use App\Models\MonitorMembership;
use App\Models\PairingRequest;
use App\Models\User;
use Closure;
use Illuminate\Contracts\Auth\Authenticatable as AuthenticatableContract;
use Illuminate\Database\QueryException;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Testing\LazilyRefreshDatabase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Str;
use Laravel\Sanctum\PersonalAccessToken;
use LogicException;
use RuntimeException;
use Tests\TestCase;

class AccessAndPairingSchemaTest extends TestCase
{
    use LazilyRefreshDatabase;

    public function test_access_schema_uses_uuid_ids_timezone_timestamps_and_named_constraints(): void
    {
        $uuidTables = [
            'monitors',
            'installations',
            'monitor_memberships',
            'invitations',
            'pairing_requests',
        ];

        foreach ($uuidTables as $table) {
            $column = DB::selectOne(
                'select data_type from information_schema.columns where table_schema = ? and table_name = ? and column_name = ?',
                ['public', $table, 'id'],
            );

            $this->assertNotNull($column, "The {$table}.id column should exist.");
            $this->assertSame('uuid', $column->data_type);
        }

        $timestampColumns = [
            ['monitors', 'created_at'],
            ['monitor_memberships', 'approved_at'],
            ['invitations', 'expires_at'],
            ['pairing_requests', 'request_expires_at'],
        ];

        foreach ($timestampColumns as [$table, $columnName]) {
            $column = DB::selectOne(
                'select data_type, datetime_precision from information_schema.columns where table_schema = ? and table_name = ? and column_name = ?',
                ['public', $table, $columnName],
            );

            $this->assertNotNull($column, "The {$table}.{$columnName} column should exist.");
            $this->assertSame('timestamp with time zone', $column->data_type);
            $this->assertSame(0, (int) $column->datetime_precision);
        }

        $tokenMorph = DB::selectOne(
            'select data_type from information_schema.columns where table_schema = ? and table_name = ? and column_name = ?',
            ['public', 'personal_access_tokens', 'tokenable_id'],
        );

        $this->assertNotNull($tokenMorph);
        $this->assertSame('uuid', $tokenMorph->data_type);

        $constraints = array_map(
            static fn (object $constraint): string => $constraint->conname,
            DB::select("select conname from pg_constraint where connamespace = 'public'::regnamespace"),
        );
        $expectedConstraints = [
            'users_firebase_identity_unique',
            'monitors_user_id_foreign',
            'monitors_user_id_unique',
            'monitor_memberships_monitor_id_foreign',
            'monitor_memberships_installation_id_foreign',
            'monitor_memberships_monitor_id_installation_id_unique',
            'monitor_memberships_role_check',
            'invitations_monitor_id_foreign',
            'invitations_issuing_installation_id_foreign',
            'invitations_secret_hash_unique',
            'pairing_requests_monitor_id_foreign',
            'pairing_requests_invitation_id_foreign',
            'pairing_requests_installation_id_foreign',
            'pairing_requests_decision_actor_membership_id_foreign',
            'pairing_requests_invitation_id_unique',
            'pairing_requests_installation_id_unique',
            'pairing_requests_status_check',
        ];

        $this->assertSame([], array_values(array_diff($expectedConstraints, $constraints)));

        $activeHostIndex = DB::selectOne(
            'select indexdef from pg_indexes where schemaname = ? and indexname = ?',
            ['public', 'monitor_memberships_one_active_host_unique'],
        );

        $this->assertNotNull($activeHostIndex);
        $this->assertStringContainsString('UNIQUE INDEX', $activeHostIndex->indexdef);
        $this->assertStringContainsString('WHERE', $activeHostIndex->indexdef);
    }

    public function test_duplicate_firebase_identity_is_rejected_by_the_database(): void
    {
        $user = User::factory()->create();

        $this->assertConstraintViolation('users_firebase_identity_unique', function () use ($user): void {
            User::factory()->create([
                'firebase_project_id' => $user->firebase_project_id,
                'firebase_uid' => $user->firebase_uid,
            ]);
        });
    }

    public function test_a_user_cannot_own_multiple_monitors(): void
    {
        $user = User::factory()->create();
        $monitor = Monitor::factory()->for($user)->create();

        $this->assertConstraintViolation('monitors_user_id_unique', function () use ($user): void {
            Monitor::factory()->for($user)->create();
        });

        $this->assertDatabaseHas('monitors', ['id' => $monitor->id]);
    }

    public function test_monitor_generation_and_reference_flag_are_cast_to_native_types(): void
    {
        $monitor = Monitor::factory()->make([
            'host_generation' => '7',
            'requires_reference' => 1,
        ]);

        $this->assertSame(7, $monitor->host_generation);
        $this->assertTrue($monitor->requires_reference);
    }

    public function test_invitation_secret_hash_is_unique(): void
    {
        $invitation = Invitation::factory()->create();

        $this->assertConstraintViolation('invitations_secret_hash_unique', function () use ($invitation): void {
            Invitation::factory()->create(['secret_hash' => $invitation->secret_hash]);
        });
    }

    public function test_pairing_request_invitation_is_unique(): void
    {
        $monitor = Monitor::factory()->create();
        $invitation = Invitation::factory()->create(['monitor_id' => $monitor->id]);
        $installation = Installation::factory()->create();

        PairingRequest::factory()->create([
            'monitor_id' => $monitor->id,
            'invitation_id' => $invitation->id,
            'installation_id' => $installation->id,
        ]);

        $this->assertConstraintViolation('pairing_requests_invitation_id_unique', function () use ($monitor, $invitation): void {
            PairingRequest::factory()->create([
                'monitor_id' => $monitor->id,
                'invitation_id' => $invitation->id,
            ]);
        });
    }

    public function test_pairing_request_installation_is_unique(): void
    {
        $monitor = Monitor::factory()->create();
        $installation = Installation::factory()->create();
        $firstInvitation = Invitation::factory()->create(['monitor_id' => $monitor->id]);
        $secondInvitation = Invitation::factory()->create(['monitor_id' => $monitor->id]);

        PairingRequest::factory()->create([
            'monitor_id' => $monitor->id,
            'invitation_id' => $firstInvitation->id,
            'installation_id' => $installation->id,
        ]);

        $this->assertConstraintViolation('pairing_requests_installation_id_unique', function () use ($monitor, $secondInvitation, $installation): void {
            PairingRequest::factory()->create([
                'monitor_id' => $monitor->id,
                'invitation_id' => $secondInvitation->id,
                'installation_id' => $installation->id,
            ]);
        });
    }

    public function test_role_and_request_status_are_cast_to_backed_enums(): void
    {
        $membership = MonitorMembership::factory()->host()->create();
        $request = PairingRequest::factory()->create([
            'monitor_id' => $membership->monitor_id,
        ]);

        $this->assertSame(AccessRole::Host, $membership->role);
        $this->assertSame(PairingRequestStatus::Pending, $request->status);
    }

    public function test_invitation_secret_hash_is_hidden_from_model_serialization(): void
    {
        $invitation = Invitation::factory()->create();

        $this->assertSame(64, strlen($invitation->secret_hash));
        $this->assertArrayNotHasKey('secret_hash', $invitation->toArray());
    }

    public function test_only_one_unrevoked_host_membership_is_allowed_per_monitor(): void
    {
        $monitor = Monitor::factory()->create();
        $firstInstallation = Installation::factory()->create();
        $secondInstallation = Installation::factory()->create();
        $firstHost = MonitorMembership::factory()->host()->create([
            'monitor_id' => $monitor->id,
            'installation_id' => $firstInstallation->id,
        ]);

        $this->assertConstraintViolation('monitor_memberships_one_active_host_unique', function () use ($monitor, $secondInstallation): void {
            MonitorMembership::factory()->host()->create([
                'monitor_id' => $monitor->id,
                'installation_id' => $secondInstallation->id,
            ]);
        });

        $firstHost->update(['revoked_at' => now()]);

        $replacementHost = MonitorMembership::factory()->host()->create([
            'monitor_id' => $monitor->id,
            'installation_id' => $secondInstallation->id,
        ]);

        $this->assertModelExists($replacementHost);
    }

    public function test_membership_role_is_limited_to_the_supported_backed_enum_values(): void
    {
        $monitor = Monitor::factory()->create();
        $installation = Installation::factory()->create();

        $this->assertConstraintViolation('monitor_memberships_role_check', function () use ($monitor, $installation): void {
            DB::table('monitor_memberships')->insert([
                'id' => (string) Str::uuid(),
                'monitor_id' => $monitor->id,
                'installation_id' => $installation->id,
                'role' => 'Observer',
                'generation' => null,
                'approved_at' => now(),
                'created_at' => now(),
                'updated_at' => now(),
            ]);
        });
    }

    public function test_pairing_request_status_is_limited_to_the_supported_backed_enum_values(): void
    {
        $pairingRequest = PairingRequest::factory()->create();

        $this->assertConstraintViolation('pairing_requests_status_check', function () use ($pairingRequest): void {
            DB::table('pairing_requests')
                ->where('id', $pairingRequest->id)
                ->update(['status' => 'Unknown']);
        });
    }

    public function test_installation_access_tokens_round_trip_uuid_morphs_and_store_only_a_hash(): void
    {
        $installation = Installation::factory()->create();

        $newAccessToken = $installation->createToken('schema-test');
        $storedToken = PersonalAccessToken::findToken($newAccessToken->plainTextToken);
        [, $plainTextToken] = explode('|', $newAccessToken->plainTextToken, 2);

        $this->assertNotNull($storedToken);
        $this->assertSame(Installation::class, $storedToken->tokenable_type);
        $this->assertSame($installation->id, $storedToken->tokenable_id);
        $this->assertSame(hash('sha256', $plainTextToken), $storedToken->token);
    }

    public function test_installation_is_an_authenticatable_api_principal(): void
    {
        $installation = Installation::factory()->make();

        $this->assertInstanceOf(AuthenticatableContract::class, $installation);
    }

    public function test_access_migration_refuses_to_drop_populated_access_tables(): void
    {
        $monitor = Monitor::factory()->create();
        $migration = require database_path('migrations/2026_11_20_000001_create_access_and_pairing_tables.php');

        try {
            $migration->down();
            $this->fail('The access migration should refuse to drop populated tables.');
        } catch (RuntimeException $exception) {
            $this->assertSame('Refusing to drop populated access and pairing tables.', $exception->getMessage());
        }

        $this->assertTrue(Schema::hasTable('monitors'));
        $this->assertDatabaseHas('monitors', ['id' => $monitor->id]);
    }

    public function test_users_migration_refuses_to_drop_populated_owner_identities(): void
    {
        $user = User::factory()->create();
        $migration = require database_path('migrations/0001_01_01_000000_create_users_table.php');

        try {
            $migration->down();
            $this->fail('The users migration should refuse to drop populated identities.');
        } catch (RuntimeException $exception) {
            $this->assertSame('Refusing to drop populated user-related tables.', $exception->getMessage());
        }

        $this->assertTrue(Schema::hasTable('users'));
        $this->assertDatabaseHas('users', ['id' => $user->id]);
    }

    public function test_users_migration_refuses_to_drop_populated_password_reset_tokens(): void
    {
        $this->assertSame(0, DB::table('users')->count());

        $record = [
            'email' => 'migration-down@example.test',
            'token' => hash('sha256', 'synthetic-password-reset'),
            'created_at' => null,
        ];
        DB::table('password_reset_tokens')->insert($record);

        $this->assertUsersMigrationDownRefusesAndRestoresSchema(
            'password_reset_tokens',
            $record,
        );
    }

    public function test_users_migration_refuses_to_drop_populated_sessions(): void
    {
        $this->assertSame(0, DB::table('users')->count());

        $record = [
            'id' => 'migration-down-session',
            'user_id' => null,
            'ip_address' => '192.0.2.10',
            'user_agent' => 'synthetic-test-agent',
            'payload' => 'synthetic-session-payload',
            'last_activity' => 1,
        ];
        DB::table('sessions')->insert($record);

        $this->assertUsersMigrationDownRefusesAndRestoresSchema(
            'sessions',
            $record,
        );
    }

    /**
     * @param  Closure(): void  $attempt
     */
    private function assertConstraintViolation(string $constraintName, Closure $attempt): void
    {
        try {
            DB::transaction($attempt);
        } catch (QueryException $exception) {
            $this->assertStringContainsString($constraintName, $exception->getMessage());

            return;
        }

        $this->fail("The database should reject a violation of {$constraintName}.");
    }

    /**
     * @param  array{email: string, token: string, created_at: null}|array{id: string, user_id: null, ip_address: string, user_agent: string, payload: string, last_activity: int}  $record
     */
    private function assertUsersMigrationDownRefusesAndRestoresSchema(
        string $recordTable,
        array $record,
    ): void {
        $migration = require database_path('migrations/0001_01_01_000000_create_users_table.php');
        $observation = [];

        try {
            DB::transaction(function () use ($migration, $recordTable, $record, &$observation): void {
                Schema::table('monitors', function (Blueprint $table): void {
                    $table->dropForeign('monitors_user_id_foreign');
                });

                try {
                    $migration->down();
                } catch (RuntimeException $exception) {
                    $observation['refusal_message'] = $exception->getMessage();
                }

                foreach (['users', 'password_reset_tokens', 'sessions'] as $table) {
                    $observation['tables_exist'][$table] = Schema::hasTable($table);
                }

                $observation['record_exists'] = Schema::hasTable($recordTable)
                    && DB::table($recordTable)->where($record)->exists();

                throw new LogicException('Roll back the users migration down probe.');
            });
        } catch (LogicException $exception) {
            $this->assertSame('Roll back the users migration down probe.', $exception->getMessage());
        }

        $tablesAfterRollback = [];

        foreach (['users', 'password_reset_tokens', 'sessions'] as $table) {
            $tablesAfterRollback[$table] = Schema::hasTable($table);
        }

        $recordTableExists = $tablesAfterRollback[$recordTable] ?? false;
        $actual = [
            'refusal_message' => $observation['refusal_message'] ?? null,
            'tables_exist_during_down' => $observation['tables_exist'] ?? [],
            'record_exists_during_down' => $observation['record_exists'] ?? false,
            'tables_exist_after_rollback' => $tablesAfterRollback,
            'users_count_after_rollback' => $tablesAfterRollback['users']
                ? DB::table('users')->count()
                : null,
            'record_count_after_rollback' => $recordTableExists
                ? DB::table($recordTable)->count()
                : null,
            'record_matches_after_rollback' => $recordTableExists
                && DB::table($recordTable)->where($record)->exists(),
            'owner_foreign_key_after_rollback' => DB::table('pg_constraint')
                ->where('conname', 'monitors_user_id_foreign')
                ->exists(),
        ];

        $this->assertSame([
            'refusal_message' => 'Refusing to drop populated user-related tables.',
            'tables_exist_during_down' => [
                'users' => true,
                'password_reset_tokens' => true,
                'sessions' => true,
            ],
            'record_exists_during_down' => true,
            'tables_exist_after_rollback' => [
                'users' => true,
                'password_reset_tokens' => true,
                'sessions' => true,
            ],
            'users_count_after_rollback' => 0,
            'record_count_after_rollback' => 1,
            'record_matches_after_rollback' => true,
            'owner_foreign_key_after_rollback' => true,
        ], $actual);
    }
}
