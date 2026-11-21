<?php

namespace Tests\Feature;

use Laravel\Sanctum\HasApiTokens;
use Tests\TestCase;

class SanctumDependencyTest extends TestCase
{
    public function test_sanctum_api_token_trait_is_installed(): void
    {
        $this->assertTrue(trait_exists(HasApiTokens::class));
    }

    public function test_sanctum_uses_bearer_tokens_without_global_expiration(): void
    {
        $this->assertSame([], config('sanctum.guard'));
        $this->assertNull(config('sanctum.expiration'));
        $this->assertFalse(config('sanctum.routes'));
    }

    public function test_sanctum_csrf_cookie_route_is_not_registered(): void
    {
        $this->get('/sanctum/csrf-cookie')->assertNotFound();
    }
}
