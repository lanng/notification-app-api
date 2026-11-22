<?php

namespace App\Support\AccessAndPairing;

use const JSON_BIGINT_AS_STRING;
use const JSON_THROW_ON_ERROR;
use const OPENSSL_KEYTYPE_RSA;

use DateInterval;
use DateTimeImmutable;
use GuzzleHttp\Client;
use GuzzleHttp\Exception\RequestException;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Promise\Create;
use GuzzleHttp\Promise\PromiseInterface;
use GuzzleHttp\Utils;
use Kreait\Firebase\Exception\Auth\AuthError;
use Kreait\Firebase\Exception\Auth\UserNotFound;
use Kreait\Firebase\Exception\AuthException;
use Kreait\Firebase\Factory;
use Kreait\Firebase\Http\HttpClientOptions;
use Kreait\Firebase\JWT\Action\FetchGooglePublicKeys;
use Kreait\Firebase\JWT\Action\FetchGooglePublicKeys\Handler;
use Kreait\Firebase\JWT\Action\FetchGooglePublicKeys\WithGuzzle;
use Kreait\Firebase\JWT\Action\VerifyIdToken\WithLcobucciJWT;
use Kreait\Firebase\JWT\Contract\Expirable;
use Kreait\Firebase\JWT\Contract\Keys;
use Kreait\Firebase\JWT\Error\FetchingGooglePublicKeysFailed;
use Kreait\Firebase\JWT\Error\IdTokenVerificationFailed;
use Kreait\Firebase\JWT\GooglePublicKeys;
use Kreait\Firebase\JWT\IdTokenVerifier;
use Kreait\Firebase\JWT\Keys\ExpiringKeys;
use Kreait\Firebase\Util;
use Psr\Clock\ClockInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use SensitiveParameter;
use stdClass;
use Throwable;
use UnexpectedValueException;

use function base64_decode;
use function base64_encode;
use function ctype_digit;
use function in_array;
use function json_decode;
use function mb_strlen;
use function openssl_pkey_get_details;
use function openssl_pkey_get_public;
use function preg_match;
use function property_exists;
use function strtr;

final class FirebaseVerificationClient
{
    private const int MAX_TOKEN_BYTES = 16_384;

    private const int MAX_CLAIM_STRING_LENGTH = 128;

    private const int MAX_EXTERNAL_REQUESTS = 5;

    private const int MAX_CERTIFICATE_CACHE_SECONDS = 3_600;

    private readonly ClockInterface $clock;

    /**
     * @var stdClass&object{keys: ?Keys}
     */
    private readonly stdClass $certificateCacheState;

    /**
     * @param  array<string, mixed>|string  $serviceAccount
     */
    public function __construct(
        private readonly string $projectId,
        #[SensitiveParameter] private readonly array|string $serviceAccount,
        private readonly ?\Closure $transport = null,
    ) {
        $this->clock = new class implements ClockInterface
        {
            public function now(): DateTimeImmutable
            {
                return DateTimeImmutable::createFromInterface(now('UTC'));
            }
        };
        $this->certificateCacheState = new stdClass;
        $this->certificateCacheState->keys = null;
    }

    public function verify(#[SensitiveParameter] string $idToken): VerifiedOwnerIdentity
    {
        if (Util::authEmulatorHost() !== null) {
            throw $this->unavailable();
        }

        $clock = $this->clock;
        $rawClaims = $this->readUnverifiedClaims($idToken);
        $this->assertRawTimeClaims($rawClaims, $clock->now()->getTimestamp());

        $requestsMade = 0;
        $authRequestStarted = false;
        $upstreamCertificateExpiry = null;
        $certificateUrls = FetchGooglePublicKeys::fromGoogle()->urls();
        $baseTransport = $this->transport ?? Utils::chooseHandler();
        $connectTimeout = config('access_pairing.firebase.connect_timeout', 3.0);
        $timeout = config('access_pairing.firebase.timeout', 5.0);

        if (! is_numeric($connectTimeout) || $connectTimeout <= 0 || ! is_numeric($timeout) || $timeout <= 0) {
            throw $this->unavailable();
        }

        $connectTimeout = (float) $connectTimeout;
        $timeout = (float) $timeout;

        $boundedTransport = function (
            RequestInterface $request,
            array $options,
        ) use (
            $baseTransport,
            $certificateUrls,
            $clock,
            &$requestsMade,
            &$authRequestStarted,
            &$upstreamCertificateExpiry,
        ): PromiseInterface {
            $requestsMade++;

            if (
                $requestsMade > self::MAX_EXTERNAL_REQUESTS
                || ! $this->isPermittedExternalRequest($request, $certificateUrls)
            ) {
                return Create::rejectionFor(new RequestException(
                    'The Firebase verification request is not permitted.',
                    $request,
                ));
            }

            $isCertificateRequest = in_array((string) $request->getUri(), $certificateUrls, true);

            if (! $isCertificateRequest) {
                $authRequestStarted = true;
            }

            $promise = $baseTransport($request, $options);

            if (! $isCertificateRequest) {
                return $promise;
            }

            return $promise->then(
                static function (ResponseInterface $response) use (
                    $clock,
                    &$upstreamCertificateExpiry,
                ): ResponseInterface {
                    $cacheControl = $response->getHeaderLine('Cache-Control');

                    if (preg_match('/max-age=(\d+)/i', $cacheControl, $matches) === 1) {
                        $maxAge = min((int) $matches[1], self::MAX_CERTIFICATE_CACHE_SECONDS);
                        $ageHeader = $response->getHeaderLine('Age');
                        $age = ctype_digit($ageHeader)
                            ? min((int) $ageHeader, self::MAX_CERTIFICATE_CACHE_SECONDS)
                            : 0;
                        $expiry = $clock->now()->add(new DateInterval('PT'.max(0, $maxAge - $age).'S'));

                        if ($upstreamCertificateExpiry === null || $expiry < $upstreamCertificateExpiry) {
                            $upstreamCertificateExpiry = $expiry;
                        }
                    }

                    return $response;
                },
            );
        };

        $certificateHandlerStack = HandlerStack::create($boundedTransport);
        $certificateHttpClient = new Client([
            'connect_timeout' => $connectTimeout,
            'timeout' => $timeout,
            'allow_redirects' => false,
            'http_errors' => false,
            'handler' => $certificateHandlerStack,
        ]);

        $sdkCertificateFetcher = new WithGuzzle($certificateHttpClient, $clock);
        $expiryProvider = static function () use (&$upstreamCertificateExpiry): ?DateTimeImmutable {
            return $upstreamCertificateExpiry;
        };
        $cappedCertificateFetcher = new class($sdkCertificateFetcher, $clock, $expiryProvider, self::MAX_CERTIFICATE_CACHE_SECONDS, $this->certificateCacheState) implements Handler
        {
            public function __construct(
                private readonly Handler $delegate,
                private readonly ClockInterface $clock,
                private readonly \Closure $upstreamExpiry,
                private readonly int $maximumCacheSeconds,
                private readonly stdClass $cacheState,
            ) {}

            public function handle(FetchGooglePublicKeys $action): Keys
            {
                $cachedKeys = $this->cacheState->keys;

                if (
                    $cachedKeys instanceof Expirable
                    && ! $cachedKeys->isExpiredAt($this->clock->now())
                ) {
                    return $cachedKeys;
                }

                $keys = $this->delegate->handle($action);
                $values = $keys->all();

                if ($values === []) {
                    throw FetchingGooglePublicKeysFailed::because(
                        'The Google public key response did not contain any usable keys.',
                    );
                }

                foreach ($values as $keyId => $value) {
                    if (! is_string($keyId) || $keyId === '' || ! is_string($value) || $value === '') {
                        throw FetchingGooglePublicKeysFailed::because(
                            'The Google public key response did not contain a usable RSA key.',
                        );
                    }

                    $publicKey = @openssl_pkey_get_public($value);
                    $details = $publicKey === false ? false : openssl_pkey_get_details($publicKey);

                    if (
                        ! is_array($details)
                        || ($details['type'] ?? null) !== OPENSSL_KEYTYPE_RSA
                        || ($details['bits'] ?? 0) < 2_048
                    ) {
                        throw FetchingGooglePublicKeysFailed::because(
                            'The Google public key response did not contain a usable RSA key.',
                        );
                    }
                }

                $now = $this->clock->now();
                $fallbackExpiry = $now->add(new DateInterval('PT'.$this->maximumCacheSeconds.'S'));
                $sdkExpiry = $keys instanceof Expirable ? $keys->expiresAt() : $fallbackExpiry;
                $maximumExpiry = $sdkExpiry < $fallbackExpiry ? $sdkExpiry : $fallbackExpiry;
                $upstreamExpiry = ($this->upstreamExpiry)();
                $expiresAt = $upstreamExpiry instanceof DateTimeImmutable && $upstreamExpiry < $maximumExpiry
                    ? $upstreamExpiry
                    : $maximumExpiry;

                $cappedKeys = ExpiringKeys::withValuesAndExpirationTime($values, $expiresAt);
                $this->cacheState->keys = $cappedKeys;

                return $cappedKeys;
            }
        };

        $keySet = new GooglePublicKeys($cappedCertificateFetcher, $clock);
        $idTokenVerifier = new IdTokenVerifier(new WithLcobucciJWT($this->projectId, $keySet, $clock));

        try {
            $verifiedToken = $idTokenVerifier->verifyIdToken($idToken);
        } catch (FetchingGooglePublicKeysFailed) {
            throw $this->unavailable();
        } catch (IdTokenVerificationFailed) {
            throw $this->unauthenticated();
        }

        $claims = $verifiedToken->payload();

        if (! $this->verifiedPayloadMatchesRawClaims($claims, $rawClaims)) {
            throw $this->unauthenticated();
        }

        $subject = $claims['sub'];
        $authTime = $claims['auth_time'];
        $provider = $this->verifiedProvider($claims);

        if (! is_string($subject) || ! is_int($authTime) || ! is_string($provider)) {
            throw $this->unauthenticated();
        }

        if ($provider !== 'google.com') {
            return new VerifiedOwnerIdentity($this->projectId, $subject, $provider, $authTime);
        }

        if (
            (is_string($this->serviceAccount) && trim($this->serviceAccount) === '')
            || (is_array($this->serviceAccount) && $this->serviceAccount === [])
        ) {
            throw $this->unavailable();
        }

        $adminHandlerStack = HandlerStack::create($boundedTransport);
        $httpClientOptions = HttpClientOptions::default()
            ->withConnectTimeout($connectTimeout)
            ->withTimeout($timeout)
            ->withGuzzleConfigOption('allow_redirects', false)
            ->withGuzzleHandler($adminHandlerStack);

        try {
            $auth = (new Factory)
                ->withProjectId($this->projectId)
                ->withClock($clock)
                ->withHttpClientOptions($httpClientOptions)
                ->withServiceAccount($this->serviceAccount)
                ->createAuth();

            $user = $auth->getUser($subject);
        } catch (UserNotFound) {
            throw $this->unauthenticated();
        } catch (AuthException $exception) {
            if (
                $exception instanceof AuthError
                && ! $authRequestStarted
                && $exception->getPrevious() instanceof \DomainException
            ) {
                throw $this->unavailable();
            }

            $unexpectedCause = $this->unexpectedCause($exception);

            if ($unexpectedCause !== null) {
                throw $unexpectedCause;
            }

            throw $this->unavailable();
        } catch (\InvalidArgumentException|UnexpectedValueException) {
            throw $this->unavailable();
        }

        if (
            ! is_string($user->uid)
            || $user->uid !== $subject
            || ! is_bool($user->disabled)
            || ($user->tokensValidAfterTime !== null && ! $user->tokensValidAfterTime instanceof DateTimeImmutable)
        ) {
            throw $this->unavailable();
        }

        if ($user->tenantId !== null) {
            throw $this->unauthenticated();
        }

        if (
            $user->disabled
            || (
                $user->tokensValidAfterTime !== null
                && $authTime < $user->tokensValidAfterTime->getTimestamp()
            )
        ) {
            throw $this->unauthenticated();
        }

        return new VerifiedOwnerIdentity($this->projectId, $subject, $provider, $authTime);
    }

    /**
     * @return array{claims: stdClass, provider: string}
     */
    private function readUnverifiedClaims(#[SensitiveParameter] string $idToken): array
    {
        if (strlen($idToken) > self::MAX_TOKEN_BYTES) {
            throw $this->unauthenticated();
        }

        $segments = explode('.', $idToken);

        if (count($segments) !== 3) {
            throw $this->unauthenticated();
        }

        $headerJson = $this->decodeBase64Url($segments[0]);
        $payloadJson = $this->decodeBase64Url($segments[1]);
        $signature = $this->decodeBase64Url($segments[2]);

        if ($headerJson === null || $payloadJson === null || $signature === null || $signature === '') {
            throw $this->unauthenticated();
        }

        try {
            $header = json_decode($headerJson, flags: JSON_THROW_ON_ERROR | JSON_BIGINT_AS_STRING);
            $claims = json_decode($payloadJson, flags: JSON_THROW_ON_ERROR | JSON_BIGINT_AS_STRING);
        } catch (\JsonException) {
            throw $this->unauthenticated();
        }

        if (! $header instanceof stdClass || ! $claims instanceof stdClass) {
            throw $this->unauthenticated();
        }

        if (
            ($header->alg ?? null) !== 'RS256'
            || ! is_string($header->kid ?? null)
            || $header->kid === ''
            || mb_strlen($header->kid) > self::MAX_CLAIM_STRING_LENGTH
            || (property_exists($header, 'typ') && $header->typ !== 'JWT')
        ) {
            throw $this->unauthenticated();
        }

        foreach (['iss', 'aud', 'sub'] as $claimName) {
            $value = $claims->{$claimName} ?? null;

            if (
                ! is_string($value)
                || $value === ''
                || mb_strlen($value) > self::MAX_CLAIM_STRING_LENGTH
            ) {
                throw $this->unauthenticated();
            }
        }

        if (
            $claims->iss !== 'https://securetoken.google.com/'.$this->projectId
            || $claims->aud !== $this->projectId
        ) {
            throw $this->unauthenticated();
        }

        foreach (['exp', 'iat', 'auth_time'] as $claimName) {
            $value = $claims->{$claimName} ?? null;

            if (! is_int($value) || $value < 0) {
                throw $this->unauthenticated();
            }
        }

        if (
            property_exists($claims, 'nbf')
            && (! is_int($claims->nbf) || $claims->nbf < 0)
        ) {
            throw $this->unauthenticated();
        }

        $firebaseClaim = $claims->firebase ?? null;
        $provider = $firebaseClaim instanceof stdClass
            ? ($firebaseClaim->sign_in_provider ?? null)
            : null;

        if (
            ! is_string($provider)
            || $provider === ''
            || mb_strlen($provider) > self::MAX_CLAIM_STRING_LENGTH
            || property_exists($firebaseClaim, 'tenant')
        ) {
            throw $this->unauthenticated();
        }

        return [
            'claims' => $claims,
            'provider' => $provider,
        ];
    }

    /**
     * @param  array{claims: stdClass, provider: string}  $rawClaims
     */
    private function assertRawTimeClaims(array $rawClaims, int $now): void
    {
        $claims = $rawClaims['claims'];

        if (
            $claims->exp <= $now
            || $claims->iat > $now
            || $claims->auth_time > $now
            || $claims->auth_time > $claims->iat
            || $claims->exp <= $claims->iat
            || $claims->exp - $claims->iat > 3_600
            || (property_exists($claims, 'nbf') && $claims->nbf > $now)
        ) {
            throw $this->unauthenticated();
        }
    }

    private function decodeBase64Url(string $segment): ?string
    {
        if (preg_match('/^[A-Za-z0-9_-]+$/D', $segment) !== 1 || strlen($segment) % 4 === 1) {
            return null;
        }

        $decoded = base64_decode(
            strtr($segment, '-_', '+/').str_repeat('=', (4 - strlen($segment) % 4) % 4),
            true,
        );

        if (
            ! is_string($decoded)
            || rtrim(strtr(base64_encode($decoded), '+/', '-_'), '=') !== $segment
        ) {
            return null;
        }

        return $decoded;
    }

    /**
     * @param  array<string, mixed>  $verifiedClaims
     * @param  array{claims: stdClass, provider: string}  $rawClaims
     */
    private function verifiedPayloadMatchesRawClaims(array $verifiedClaims, array $rawClaims): bool
    {
        $raw = $rawClaims['claims'];

        foreach (['iss', 'sub', 'exp', 'iat', 'auth_time'] as $claimName) {
            if (! array_key_exists($claimName, $verifiedClaims) || $verifiedClaims[$claimName] !== $raw->{$claimName}) {
                return false;
            }
        }

        if (property_exists($raw, 'nbf') && ($verifiedClaims['nbf'] ?? null) !== $raw->nbf) {
            return false;
        }

        if (($verifiedClaims['aud'] ?? null) !== [$raw->aud]) {
            return false;
        }

        $verifiedFirebaseClaim = $verifiedClaims['firebase'] ?? null;

        if ($verifiedFirebaseClaim instanceof stdClass) {
            $verifiedProvider = $verifiedFirebaseClaim->sign_in_provider ?? null;

            if (property_exists($verifiedFirebaseClaim, 'tenant')) {
                return false;
            }
        } elseif (is_array($verifiedFirebaseClaim)) {
            $verifiedProvider = $verifiedFirebaseClaim['sign_in_provider'] ?? null;

            if (array_key_exists('tenant', $verifiedFirebaseClaim)) {
                return false;
            }
        } else {
            return false;
        }

        return $verifiedProvider === $rawClaims['provider'];
    }

    /**
     * @param  array<string, mixed>  $verifiedClaims
     */
    private function verifiedProvider(array $verifiedClaims): mixed
    {
        $firebaseClaim = $verifiedClaims['firebase'] ?? null;

        if ($firebaseClaim instanceof stdClass) {
            return $firebaseClaim->sign_in_provider ?? null;
        }

        if (is_array($firebaseClaim)) {
            return $firebaseClaim['sign_in_provider'] ?? null;
        }

        return null;
    }

    /**
     * @param  list<string>  $certificateUrls
     */
    private function isPermittedExternalRequest(
        RequestInterface $request,
        array $certificateUrls,
    ): bool {
        $uri = $request->getUri();
        $url = (string) $uri;

        if ($uri->getScheme() !== 'https') {
            return false;
        }

        if ($request->getMethod() === 'GET' && in_array($url, $certificateUrls, true)) {
            return true;
        }

        if (
            $request->getMethod() === 'POST'
            && $url === 'https://oauth2.googleapis.com/token'
        ) {
            return true;
        }

        return $request->getMethod() === 'POST'
            && $url === 'https://identitytoolkit.googleapis.com/v1/projects/'.$this->projectId.'/accounts:lookup';
    }

    private function unexpectedCause(Throwable $exception): ?Throwable
    {
        $cause = $exception->getPrevious();

        while ($cause !== null) {
            if ($cause instanceof \Error || $cause instanceof \LogicException) {
                return $cause;
            }

            $cause = $cause->getPrevious();
        }

        return null;
    }

    private function unauthenticated(): AccessFailure
    {
        return new AccessFailure(
            401,
            'access_unauthenticated',
            'Autenticação necessária.',
        );
    }

    private function unavailable(): AccessFailure
    {
        return new AccessFailure(
            503,
            'identity_verification_unavailable',
            'Verificação de identidade indisponível.',
        );
    }
}
