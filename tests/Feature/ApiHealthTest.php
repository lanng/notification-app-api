<?php

namespace Tests\Feature;

use Tests\TestCase;

class ApiHealthTest extends TestCase
{
    public function test_health_endpoint_returns_only_a_success_status(): void
    {
        $response = $this->get('/api/health');

        $response->assertOk()->assertExactJson([
            'status' => 'ok',
        ]);
    }

    public function test_unknown_api_route_returns_a_json_not_found_message(): void
    {
        $response = $this->get('/api/does-not-exist');

        $response->assertNotFound()->assertJsonStructure([
            'message',
        ]);
    }
}
