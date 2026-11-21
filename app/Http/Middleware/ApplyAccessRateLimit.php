<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Routing\Middleware\ThrottleRequests;
use Symfony\Component\HttpFoundation\Response;

final class ApplyAccessRateLimit
{
    public function __construct(private ThrottleRequests $throttleRequests) {}

    /**
     * @param  Closure(Request): Response  $next
     */
    public function handle(Request $request, Closure $next, string $limiterName): Response
    {
        return $this->throttleRequests->handle($request, $next, $limiterName);
    }
}
