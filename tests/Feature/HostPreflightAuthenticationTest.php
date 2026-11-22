<?php

namespace Tests\Feature;

use App\Models\Invitation;
use App\Models\Monitor;
use App\Models\MonitorMembership;
use App\Models\PairingRequest;
use App\Support\AccessAndPairing\AccessAndPairing;
use App\Support\AccessAndPairing\VerifiedOwnerIdentity;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Events\Dispatcher;
use Illuminate\Foundation\Testing\LazilyRefreshDatabase;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\DataProvider;
use Tests\Support\AccessAndPairingFixtures;
use Tests\TestCase;

class HostPreflightAuthenticationTest extends TestCase
{
    use LazilyRefreshDatabase;

    /**
     * @return array<string, array{string, string}>
     */
    public static function hostMonitorRoutes(): array
    {
        return [
            'controller preflight' => ['GET', '/api/v1/monitors/%s/supports'],
            'issuance limiter preflight' => ['POST', '/api/v1/monitors/%s/invitations'],
        ];
    }

    #[DataProvider('hostMonitorRoutes')]
    public function test_returns_401_when_a_host_swap_revokes_the_token_after_sanctum_authentication(
        string $method,
        string $routeTemplate,
    ): void {
        $fixtures = new AccessAndPairingFixtures($this);
        $host = $fixtures->createHost();
        $invitationCountBeforeRequest = Invitation::query()
            ->where('monitor_id', $host['monitor']->id)
            ->count();
        $pairingRequestCountBeforeRequest = PairingRequest::query()
            ->where('monitor_id', $host['monitor']->id)
            ->count();
        $connection = DB::connection('pgsql');
        $baselineTransactionLevel = $connection->transactionLevel();
        $originalDispatcher = $connection->getEventDispatcher();

        if (! $originalDispatcher instanceof Dispatcher) {
            throw new \LogicException('A database event dispatcher is required for the authentication interleave.');
        }

        $testDispatcher = clone $originalDispatcher;
        $sanctumAuthenticationUpdateObserved = false;
        $hostSwapInProgress = false;
        $hostSwapCompleted = false;
        $preflightMembershipQueryObserved = false;
        $preflightTokenReadCount = 0;
        $preflightTokenReadSql = null;
        $preflightTokenReadTransactionLevel = null;
        $swapResult = null;

        $testDispatcher->listen(
            QueryExecuted::class,
            function (QueryExecuted $query) use (
                $host,
                &$sanctumAuthenticationUpdateObserved,
                &$hostSwapInProgress,
                &$hostSwapCompleted,
                &$preflightMembershipQueryObserved,
                &$preflightTokenReadCount,
                &$preflightTokenReadSql,
                &$preflightTokenReadTransactionLevel,
                &$swapResult,
            ): void {
                if (
                    ! $sanctumAuthenticationUpdateObserved
                    && $this->isSanctumLastUsedUpdate($query, (int) $host['accessToken']->getKey())
                ) {
                    $sanctumAuthenticationUpdateObserved = true;
                    $hostSwapInProgress = true;

                    try {
                        $identity = new VerifiedOwnerIdentity(
                            (string) config('access_pairing.owner.firebase_project_id'),
                            (string) config('access_pairing.owner.firebase_uid'),
                            'google.com',
                            now('UTC')->getTimestamp(),
                        );
                        $swapResult = app(AccessAndPairing::class)->activateHost($identity, true, '1');
                    } finally {
                        $hostSwapInProgress = false;
                    }

                    $hostSwapCompleted = true;

                    return;
                }

                if (
                    $hostSwapCompleted
                    && ! $hostSwapInProgress
                    && $this->isCurrentActorTokenRead($query, (int) $host['accessToken']->getKey())
                ) {
                    $preflightTokenReadCount++;
                    $preflightTokenReadSql = $query->sql;
                    $preflightTokenReadTransactionLevel = DB::connection('pgsql')->transactionLevel();
                }

                if (
                    $hostSwapCompleted
                    && ! $hostSwapInProgress
                    && $this->isMonitorMembershipRead($query->sql)
                ) {
                    $preflightMembershipQueryObserved = true;
                }
            },
        );

        $connection->setEventDispatcher($testDispatcher);

        try {
            $response = $fixtures->requestJson(
                $method,
                sprintf($routeTemplate, $host['monitor']->id),
                '{}',
                ['Authorization' => 'Bearer '.$host['token']],
            );
        } finally {
            $connection->setEventDispatcher($originalDispatcher);
        }

        $this->assertTrue($sanctumAuthenticationUpdateObserved);
        $this->assertTrue($hostSwapCompleted);

        if (! is_array($swapResult)) {
            throw new \LogicException('The actual host-swap operation did not return its activation result.');
        }

        $this->assertFalse($swapResult['firstActivation']);
        $this->assertSame('2', $swapResult['data']['generation']);

        $response->assertUnauthorized()->assertExactJson([
            'code' => 'access_unauthenticated',
            'message' => 'A credencial não é válida.',
        ]);

        $this->assertSame(1, $preflightTokenReadCount);
        $this->assertIsString($preflightTokenReadSql);
        $this->assertStringNotContainsString('for update', strtolower($preflightTokenReadSql));
        $this->assertSame($baselineTransactionLevel, $preflightTokenReadTransactionLevel);
        $this->assertFalse($preflightMembershipQueryObserved);

        $monitor = Monitor::query()->findOrFail($host['monitor']->id);
        $this->assertSame(2, $monitor->host_generation);
        $this->assertSame(0, MonitorMembership::query()
            ->whereKey($host['membership']->id)
            ->whereNull('revoked_at')
            ->count());
        $this->assertSame(1, MonitorMembership::query()
            ->where('monitor_id', $monitor->id)
            ->where('installation_id', $swapResult['data']['installationId'])
            ->where('role', 'Host')
            ->where('generation', 2)
            ->whereNull('revoked_at')
            ->count());
        $this->assertDatabaseMissing('personal_access_tokens', [
            'id' => $host['accessToken']->getKey(),
        ]);
        $this->assertSame($invitationCountBeforeRequest, Invitation::query()
            ->where('monitor_id', $monitor->id)
            ->count());
        $this->assertSame($pairingRequestCountBeforeRequest, PairingRequest::query()
            ->where('monitor_id', $monitor->id)
            ->count());
    }

    private function isSanctumLastUsedUpdate(QueryExecuted $query, int $tokenId): bool
    {
        $sql = strtolower(ltrim($query->sql));
        $bindings = array_map('strval', $query->bindings);

        return str_starts_with($sql, 'update ')
            && str_contains($sql, 'personal_access_tokens')
            && str_contains($sql, 'last_used_at')
            && in_array((string) $tokenId, $bindings, true);
    }

    private function isMonitorMembershipRead(string $sql): bool
    {
        $normalizedSql = strtolower(ltrim($sql));

        return str_starts_with($normalizedSql, 'select ')
            && str_contains($normalizedSql, 'monitor_memberships');
    }

    private function isCurrentActorTokenRead(QueryExecuted $query, int $tokenId): bool
    {
        $sql = strtolower(ltrim($query->sql));
        $bindings = array_map('strval', $query->bindings);

        return str_starts_with($sql, 'select ')
            && str_contains($sql, 'personal_access_tokens')
            && in_array((string) $tokenId, $bindings, true);
    }
}
