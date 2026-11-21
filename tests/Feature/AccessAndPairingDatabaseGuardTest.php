<?php

namespace Tests\Feature;

use Illuminate\Contracts\Foundation\Application;
use Illuminate\Foundation\Testing\DatabaseTransactions;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\DataProvider;
use RuntimeException;
use Tests\Support\SafePostgresTestingDatabase;
use Tests\TestCase;
use Throwable;

class AccessAndPairingDatabaseGuardTest extends TestCase
{
    public static function unsafeDatabaseConfigurations(): array
    {
        return [
            'non-testing environment' => [['app.env' => 'local']],
            'non-postgres default connection' => [['database.default' => 'sqlite']],
            'in-memory sqlite connection' => [[
                'database.connections.pgsql.driver' => 'sqlite',
                'database.connections.pgsql.database' => ':memory:',
            ]],
            'non-container database host' => [['database.connections.pgsql.host' => 'localhost']],
            'non-testing database name' => [['database.connections.pgsql.database' => 'tag_alert']],
            'database URL' => [['database.connections.pgsql.url' => 'postgresql://unsafe.invalid/testing']],
            'non-public search path' => [['database.connections.pgsql.search_path' => 'tenant']],
        ];
    }

    public function test_safe_postgresql_testing_database_is_accepted(): void
    {
        SafePostgresTestingDatabase::assertSafe($this->app);

        $this->assertSame('testing', DB::connection('pgsql')->getDatabaseName());
    }

    public function test_database_test_trait_is_refused_before_database_access(): void
    {
        config(['database.default' => 'unsafe']);

        $testCase = new class('trait guard') extends TestCase
        {
            use RefreshDatabase;

            public function setApplication(Application $app): void
            {
                $this->app = $app;
            }

            public function setUpTraitsForSafetyCheck(): array
            {
                return $this->setUpTraits();
            }
        };
        $testCase->setApplication($this->app);

        try {
            $testCase->setUpTraitsForSafetyCheck();
            $this->fail('The database test trait should have been rejected.');
        } catch (RuntimeException $exception) {
            $this->assertSame(
                'Refusing database access outside the PostgreSQL testing database.',
                $exception->getMessage(),
            );
        }

        $this->assertSame([], DB::getConnections());
    }

    public function test_database_transaction_trait_is_refused_before_database_access(): void
    {
        config(['database.default' => 'unconfigured-unsafe']);

        $testCase = new class('transaction trait guard') extends TestCase
        {
            use DatabaseTransactions;

            public function setApplication(Application $app): void
            {
                $this->app = $app;
            }

            public function setUpTraitsForSafetyCheck(): array
            {
                return $this->setUpTraits();
            }
        };
        $testCase->setApplication($this->app);

        $exception = null;

        try {
            $testCase->setUpTraitsForSafetyCheck();
        } catch (Throwable $caughtException) {
            $exception = $caughtException;
        }

        $this->assertSame([], DB::getConnections());
        $this->assertInstanceOf(RuntimeException::class, $exception);
        $this->assertSame(
            'Refusing database access outside the PostgreSQL testing database.',
            $exception->getMessage(),
        );
    }

    /** @param array<string, mixed> $unsafeConfiguration */
    #[DataProvider('unsafeDatabaseConfigurations')]
    public function test_unsafe_database_configuration_is_rejected_before_a_connection_is_opened(array $unsafeConfiguration): void
    {
        config($unsafeConfiguration);

        try {
            SafePostgresTestingDatabase::assertSafe($this->app);
            $this->fail('The database configuration should have been rejected.');
        } catch (RuntimeException $exception) {
            $this->assertSame(
                'Refusing database access outside the PostgreSQL testing database.',
                $exception->getMessage(),
            );
        }

        $this->assertSame([], DB::getConnections());
    }
}
