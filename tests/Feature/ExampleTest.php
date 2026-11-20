<?php

namespace Tests\Feature;

// use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\TestCase;

class ExampleTest extends TestCase
{
    public function test_the_root_route_returns_not_found_without_a_frontend(): void
    {
        $response = $this->get('/');

        $response->assertNotFound();
    }
}
