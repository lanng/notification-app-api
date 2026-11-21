<?php

namespace App\Providers;

use App\Models\Installation;
use App\Support\AccessAndPairing\AccessAndPairing;
use App\Support\AccessAndPairing\AccessContext;
use App\Support\AccessAndPairing\AccessFailure;
use App\Support\AccessAndPairing\DisabledOwnerIdentityVerifier;
use App\Support\AccessAndPairing\OwnerIdentityVerifier;
use App\Support\AccessAndPairing\VerifiedOwnerIdentity;
use App\Support\ApiV1\ApiProblem;
use App\Support\ApiV1\JsonTypes;
use Illuminate\Cache\RateLimiting\Limit;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Support\ServiceProvider;
use Laravel\Sanctum\PersonalAccessToken;
use Laravel\Sanctum\Sanctum;
use LogicException;

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
        RateLimiter::for('ap5.redeem.ip', fn (Request $request): Limit => Limit::perMinute(10)
            ->by('ap5:redeem:ip:'.$this->directRemoteAddress($request)));
        RateLimiter::for('ap5.redeem.secret', function (Request $request): Limit {
            $payload = json_decode($request->getContent());
            $secret = $payload instanceof \stdClass
                ? ($payload->invitationSecret ?? null)
                : null;

            if (! is_string($secret) || $secret === '') {
                return Limit::none();
            }

            return Limit::perMinute(5)->by(
                'ap5:redeem:secret:'.$this->keyedDigest($secret),
            );
        });
        RateLimiter::for('ap5.owner.ip', fn (Request $request): Limit => Limit::perMinute(10)
            ->by('ap5:owner:ip:'.$this->directRemoteAddress($request)));
        RateLimiter::for('ap5.owner.identity', function (Request $request): Limit {
            $identity = $request->attributes->get('access.owner_identity');

            if (! $identity instanceof VerifiedOwnerIdentity) {
                throw new LogicException('The owner identity limiter must run after identity verification.');
            }

            return Limit::perMinute(10)->by(
                'ap5:owner:identity:'.$this->keyedDigest(
                    $identity->firebaseProjectId."\0".$identity->firebaseUid,
                ),
            );
        });
        RateLimiter::for('ap5.invitation.issue', function (Request $request): Limit {
            $context = $request->attributes->get(AccessContext::REQUEST_ATTRIBUTE);

            if (! $context instanceof AccessContext) {
                throw new LogicException('The invitation issuer limiter must run after installation authentication.');
            }

            $monitorId = app(AccessAndPairing::class)
                ->authorizedHostMonitorId($context);

            return Limit::perMinute(10)->by('ap5:invitation:monitor:'.$monitorId);
        });
        RateLimiter::for('ap5.pairing.poll', function (Request $request): Limit {
            $context = $request->attributes->get(AccessContext::REQUEST_ATTRIBUTE);

            if (! $context instanceof AccessContext) {
                throw new LogicException('The pairing poll limiter must run after installation authentication.');
            }

            return Limit::perMinute(30)->by(
                'ap5:pairing:poll:installation:'.$context->installationId,
            );
        });

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

    private function directRemoteAddress(Request $request): string
    {
        $remoteAddress = $request->server->get('REMOTE_ADDR');

        return is_string($remoteAddress) && $remoteAddress !== ''
            ? $remoteAddress
            : 'unknown';
    }

    private function keyedDigest(string $value): string
    {
        $applicationKey = config('app.key');

        if (! is_string($applicationKey) || $applicationKey === '') {
            throw new LogicException('The application key is required for access rate-limit keys.');
        }

        return hash_hmac('sha256', $value, $applicationKey);
    }
}
