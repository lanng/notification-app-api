<?php

namespace Tests\Feature;

use Illuminate\Support\Facades\DB;
use Tests\TestCase;

class PostgresConnectionTest extends TestCase
{
    public function test_testing_database_is_a_real_postgresql_database(): void
    {
        $this->assertSame('pgsql', config('database.default'));
        $this->assertSame('testing', config('database.connections.pgsql.database'));

        $database = DB::selectOne('select current_database() as name');

        $this->assertSame('testing', $database->name);
    }
}
