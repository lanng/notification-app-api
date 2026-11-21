<?php

namespace App\Http\Middleware;

use App\Support\AccessAndPairing\OwnerIdentityVerifier;
use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

final class VerifyOwnerIdentity
{
    public function __construct(private OwnerIdentityVerifier $verifier) {}

    /**
     * @param  Closure(Request): Response  $next
     */
    public function handle(Request $request, Closure $next): Response
    {
        $request->attributes->set(
            'access.owner_identity',
            $this->verifier->verify($request),
        );

        return $next($request);
    }
}
