<?php

namespace Tests\Support;

use App\Support\AccessAndPairing\OwnerIdentityVerifier;
use App\Support\AccessAndPairing\VerifiedOwnerIdentity;
use Illuminate\Support\Facades\DB;
use Illuminate\Testing\TestResponse;
use RuntimeException;
use Tests\TestCase;

final class AccessAndPairingWorkerTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        SafePostgresTestingDatabase::assertSafe($this->app);

        $applicationName = getenv('AP_WORKER_APPLICATION_NAME');
        $configCachePath = getenv('APP_CONFIG_CACHE');

        if (
            ! is_string($applicationName)
            || $applicationName === ''
            || ! is_string($configCachePath)
            || $configCachePath === ''
            || file_exists($configCachePath)
        ) {
            throw new RuntimeException('The access-pairing worker environment is unsafe.');
        }

        $expectedEnvironment = [
            'APP_ENV' => 'testing',
            'DB_CONNECTION' => 'pgsql',
            'DB_HOST' => (string) config('database.connections.pgsql.host'),
            'DB_PORT' => (string) config('database.connections.pgsql.port'),
            'DB_DATABASE' => 'testing',
            'DB_USERNAME' => (string) config('database.connections.pgsql.username'),
            'DB_PASSWORD' => (string) config('database.connections.pgsql.password'),
            'APP_KEY' => (string) config('app.key'),
        ];

        foreach ($expectedEnvironment as $name => $expectedValue) {
            if (getenv($name) !== $expectedValue) {
                throw new RuntimeException('The access-pairing worker configuration is unsafe.');
            }
        }

        if ($this->app->configurationIsCached()) {
            throw new RuntimeException('The access-pairing worker loaded a cached configuration.');
        }

        $database = DB::connection('pgsql')->selectOne(
            'select current_setting(\'application_name\') as application_name',
        );

        if ($database->application_name !== $applicationName) {
            throw new RuntimeException('The access-pairing worker database identity is unsafe.');
        }
    }

    public function test_runs_one_http_request_and_writes_only_a_sanitized_result(): void
    {
        $inputJson = getenv('AP_WORKER_INPUT');
        $resultPath = getenv('AP_WORKER_RESULT_PATH');
        $fixedUtcTime = getenv('AP_WORKER_FIXED_UTC');

        if (
            ! is_string($inputJson)
            || ! is_string($resultPath)
            || ! is_string($fixedUtcTime)
            || $resultPath === ''
            || file_exists($resultPath)
        ) {
            throw new RuntimeException('The access-pairing worker input is unsafe.');
        }

        $input = json_decode($inputJson, true, flags: JSON_THROW_ON_ERROR);

        if (! is_array($input) || ! is_string($input['operation'] ?? null)) {
            throw new RuntimeException('The access-pairing worker input is invalid.');
        }

        $this->travelTo($fixedUtcTime);

        $fixtures = new AccessAndPairingFixtures($this);
        $response = match ($input['operation']) {
            'redeem' => $fixtures->requestJson(
                'POST',
                '/api/v1/pairing-requests',
                json_encode([
                    'invitationSecret' => $input['invitationSecret'],
                    'installationLabel' => $input['installationLabel'] ?? null,
                ], JSON_THROW_ON_ERROR),
                remoteAddress: $input['remoteAddress'],
            ),
            'approve' => $fixtures->requestJson(
                'POST',
                "/api/v1/monitors/{$input['monitorId']}/pairing-requests/{$input['requestId']}/approval",
                '{}',
                ['Authorization' => 'Bearer '.$input['hostToken']],
                $input['remoteAddress'],
            ),
            'reject' => $fixtures->requestJson(
                'POST',
                "/api/v1/monitors/{$input['monitorId']}/pairing-requests/{$input['requestId']}/rejection",
                '{}',
                ['Authorization' => 'Bearer '.$input['hostToken']],
                $input['remoteAddress'],
            ),
            'activate' => $this->activateHost($fixtures, $input),
            default => throw new RuntimeException('The access-pairing worker operation is invalid.'),
        };

        $result = [
            'status' => $response->getStatusCode(),
            'response' => $this->sanitize($response->json()),
        ];
        $encodedResult = json_encode($result, JSON_THROW_ON_ERROR);

        if (file_put_contents($resultPath, $encodedResult, LOCK_EX) !== strlen($encodedResult)) {
            throw new RuntimeException('The access-pairing worker result could not be written.');
        }
    }

    /**
     * @param  array<string, mixed>  $input
     */
    private function activateHost(AccessAndPairingFixtures $fixtures, array $input): TestResponse
    {
        $projectId = getenv('ACCESS_PAIRING_OWNER_FIREBASE_PROJECT_ID');
        $firebaseUid = getenv('ACCESS_PAIRING_OWNER_FIREBASE_UID');
        $authTime = getenv('AP_WORKER_OWNER_AUTH_TIME');

        if (
            ! is_string($projectId)
            || ! is_string($firebaseUid)
            || ! is_string($authTime)
            || ! ctype_digit($authTime)
        ) {
            throw new RuntimeException('The access-pairing worker identity is unsafe.');
        }

        app()->instance(
            OwnerIdentityVerifier::class,
            new FakeOwnerIdentityVerifier(
                new VerifiedOwnerIdentity(
                    $projectId,
                    $firebaseUid,
                    'google.com',
                    (int) $authTime,
                ),
            ),
        );

        return $fixtures->requestJson(
            'POST',
            '/api/v1/owner/host-activations',
            json_encode([
                'confirmation' => true,
                'expectedGeneration' => $input['expectedGeneration'],
            ], JSON_THROW_ON_ERROR),
            ['Authorization' => 'Bearer '.FakeOwnerIdentityVerifier::TEST_BEARER_TOKEN],
            $input['remoteAddress'],
        );
    }

    private function sanitize(mixed $value): mixed
    {
        if (! is_array($value)) {
            return $value;
        }

        $sanitized = [];

        foreach ($value as $key => $item) {
            if (
                is_string($key)
                && in_array(strtolower($key), ['accesstoken', 'invitationsecret'], true)
            ) {
                continue;
            }

            $sanitized[$key] = $this->sanitize($item);
        }

        return $sanitized;
    }
}
