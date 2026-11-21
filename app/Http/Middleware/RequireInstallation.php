<?php

namespace App\Http\Middleware;

use App\Models\Installation;
use App\Support\AccessAndPairing\AccessContext;
use App\Support\AccessAndPairing\AccessFailure;
use Closure;
use Illuminate\Http\Request;
use Laravel\Sanctum\PersonalAccessToken;
use Symfony\Component\HttpFoundation\Response;

final class RequireInstallation
{
    /**
     * Handle an incoming request.
     *
     * @param  Closure(Request): (Response)  $next
     */
    public function handle(Request $request, Closure $next): Response
    {
        $installation = $request->user();
        $accessToken = $installation instanceof Installation
            ? $installation->currentAccessToken()
            : null;

        $accessTokenId = $accessToken instanceof PersonalAccessToken
            ? (string) $accessToken->getKey()
            : '';

        if (
            ! $installation instanceof Installation
            || ! $accessToken instanceof PersonalAccessToken
            || ! $accessToken->exists
            || preg_match('/\A[1-9][0-9]*\z/', $accessTokenId) !== 1
            || strlen($accessTokenId) > strlen((string) PHP_INT_MAX)
            || (
                strlen($accessTokenId) === strlen((string) PHP_INT_MAX)
                && strcmp($accessTokenId, (string) PHP_INT_MAX) > 0
            )
        ) {
            throw new AccessFailure(401, 'access_unauthenticated', 'A credencial não é válida.');
        }

        $request->attributes->set(
            AccessContext::REQUEST_ATTRIBUTE,
            new AccessContext(
                (string) $installation->getKey(),
                (int) $accessTokenId,
            ),
        );

        return $next($request);
    }
}
