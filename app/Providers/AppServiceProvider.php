<?php

namespace App\Providers;

use App\Models\Installation;
use App\Support\AccessAndPairing\AccessFailure;
use App\Support\AccessAndPairing\DisabledOwnerIdentityVerifier;
use App\Support\AccessAndPairing\OwnerIdentityVerifier;
use App\Support\ApiV1\ApiProblem;
use App\Support\ApiV1\JsonTypes;
use Illuminate\Http\Request;
use Illuminate\Support\ServiceProvider;
use Laravel\Sanctum\PersonalAccessToken;
use Laravel\Sanctum\Sanctum;

class AppServiceProvider extends ServiceProvider
{
    /**
     * Register any application services.
     */
    public function register(): void
    {
        $this->app->bind(OwnerIdentityVerifier::class, DisabledOwnerIdentityVerifier::class);
    }

    /**
     * Bootstrap any application services.
     */
    public function boot(): void
    {
        Sanctum::getAccessTokenFromRequestUsing(static function (Request $request): ?string {
            $bearerToken = $request->bearerToken();

            if ($bearerToken === null || $bearerToken === '') {
                return null;
            }

            if (str_contains($bearerToken, '|')) {
                [$tokenId, $secret] = explode('|', $bearerToken, 2);

                if (
                    $tokenId === ''
                    || $secret === ''
                    || strlen($tokenId) > strlen((string) PHP_INT_MAX)
                ) {
                    return null;
                }

                try {
                    JsonTypes::requireDecimalString($tokenId, 'token', positive: true);
                } catch (ApiProblem) {
                    return null;
                }
            }

            $accessToken = PersonalAccessToken::findToken($bearerToken);

            if ($accessToken === null) {
                return null;
            }

            if ($accessToken->tokenable_type !== (new Installation)->getMorphClass()) {
                throw new AccessFailure(401, 'access_unauthenticated', 'A credencial não é válida.');
            }

            return $bearerToken;
        });

        Sanctum::authenticateAccessTokensUsing(
            static fn (PersonalAccessToken $accessToken, bool $isValid): bool => $isValid
                && ($accessToken->expires_at === null || $accessToken->expires_at->isAfter(now('UTC'))),
        );
    }
}
