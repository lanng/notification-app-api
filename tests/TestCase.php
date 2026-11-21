<?php

namespace Tests;

use Illuminate\Foundation\Testing\DatabaseMigrations;
use Illuminate\Foundation\Testing\DatabaseTransactions;
use Illuminate\Foundation\Testing\DatabaseTruncation;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Foundation\Testing\TestCase as BaseTestCase;
use Tests\Support\SafePostgresTestingDatabase;

abstract class TestCase extends BaseTestCase
{
    protected function setUpTraits(): array
    {
        $traits = class_uses_recursive(static::class);

        if (
            isset($traits[RefreshDatabase::class])
            || isset($traits[DatabaseMigrations::class])
            || isset($traits[DatabaseTruncation::class])
            || isset($traits[DatabaseTransactions::class])
        ) {
            SafePostgresTestingDatabase::assertSafe($this->app);
        }

        return parent::setUpTraits();
    }
}
