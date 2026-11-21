<?php

namespace Tests\Support;

use Illuminate\Contracts\Foundation\Application;
use Illuminate\Database\DatabaseManager;
use RuntimeException;

class SafePostgresTestingDatabase
{
    private const REFUSAL_MESSAGE = 'Refusing database access outside the PostgreSQL testing database.';

    public static function assertSafe(Application $app): void
    {
        $config = $app->make('config');
        $connection = $config->get('database.connections.pgsql', []);

        if (
            $config->get('app.env') !== 'testing'
            || $config->get('database.default') !== 'pgsql'
            || ($connection['driver'] ?? null) !== 'pgsql'
            || ($connection['host'] ?? null) !== 'pgsql'
            || ($connection['database'] ?? null) !== 'testing'
            || ! in_array($connection['url'] ?? null, [null, ''], true)
            || ($connection['search_path'] ?? null) !== 'public'
        ) {
            throw new RuntimeException(self::REFUSAL_MESSAGE);
        }

        $database = $app->make(DatabaseManager::class)
            ->connection('pgsql')
            ->selectOne('select current_database() as database_name, current_schema() as schema_name');

        if ($database->database_name !== 'testing' || $database->schema_name !== 'public') {
            throw new RuntimeException(self::REFUSAL_MESSAGE);
        }
    }
}
