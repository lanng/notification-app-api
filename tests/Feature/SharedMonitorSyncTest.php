<?php

namespace Tests\Feature;

use App\Enums\AccessRole;
use App\Models\Installation;
use App\Models\Monitor;
use App\Models\MonitorMembership;
use App\Support\SharedMonitor\SharedAlertPushDispatcher;
use App\Support\SharedMonitor\SharedAlertPushEvent;
use Illuminate\Foundation\Testing\LazilyRefreshDatabase;
use Illuminate\Support\Str;
use Tests\TestCase;

class SharedMonitorSyncTest extends TestCase
{
    use LazilyRefreshDatabase;

    /** @var list<array{tokens: list<string>, event: SharedAlertPushEvent}> */
    private array $dispatchedPushes = [];

    /** @var list<string> */
    private array $invalidTokensToReturn = [];

    protected function setUp(): void
    {
        parent::setUp();

        $this->dispatchedPushes = [];
        $this->invalidTokensToReturn = [];

        $test = $this;
        $this->app->instance(SharedAlertPushDispatcher::class, new class($test) implements SharedAlertPushDispatcher
        {
            public function __construct(private readonly SharedMonitorSyncTest $test) {}

            /**
             * @param  list<string>  $fcmTokens
             * @return list<string>
             */
            public function dispatchToTokens(array $fcmTokens, SharedAlertPushEvent $event): array
            {
                $this->test->recordPush($fcmTokens, $event);

                return $this->test->invalidTokens();
            }
        });
    }

    /**
     * @param  list<string>  $tokens
     */
    public function recordPush(array $tokens, SharedAlertPushEvent $event): void
    {
        $this->dispatchedPushes[] = [
            'tokens' => $tokens,
            'event' => $event,
        ];
    }

    /**
     * @return list<string>
     */
    public function invalidTokens(): array
    {
        return $this->invalidTokensToReturn;
    }

    public function test_host_publishes_snapshot_and_sanitized_history_and_support_reads_them(): void
    {
        $this->travelTo('2026-11-25 14:00:00 UTC');
        $setup = $this->createHostAndSupport();

        $this->getJson('/api/v1/monitors/'.$setup['monitor']->id.'/snapshot', [
            'Authorization' => 'Bearer '.$setup['supportToken'],
        ])->assertOk()->assertExactJson(['data' => null]);

        $this->app['auth']->forgetGuards();

        $putResponse = $this->putJson(
            '/api/v1/monitors/'.$setup['monitor']->id.'/snapshot',
            [
                'balanceCents' => 35_000,
                'limitCents' => 30_000,
                'repeatMinutes' => 15,
                'pauseMinutes' => 30,
                'needsReference' => false,
                'alertCycleId' => null,
                'alertOpenedAtMs' => null,
                'alertEmissionCount' => 0,
                'lastObservedAtMs' => 1_764_079_100_000,
                'referenceConfirmedAtMs' => 1_764_070_000_000,
                'entries' => [
                    [
                        'hostEntryId' => 10,
                        'kind' => 'Reference',
                        'amountCents' => 40_000,
                        'balanceAfterCents' => 40_000,
                        'recordedAtMs' => 1_764_070_000_000,
                    ],
                    [
                        'hostEntryId' => 11,
                        'kind' => 'TagDebit',
                        'amountCents' => -5_000,
                        'balanceAfterCents' => 35_000,
                        'recordedAtMs' => 1_764_075_000_000,
                    ],
                    [
                        'hostEntryId' => 12,
                        'kind' => 'PixCredit',
                        'amountCents' => 10_000,
                        'balanceAfterCents' => 45_000,
                        'recordedAtMs' => 1_764_076_000_000,
                    ],
                ],
            ],
            ['Authorization' => 'Bearer '.$setup['hostToken']],
        );

        $putResponse->assertOk()
            ->assertJsonPath('data.monitorId', $setup['monitor']->id)
            ->assertJsonPath('data.balanceCents', 35_000)
            ->assertJsonPath('data.limitCents', 30_000)
            ->assertJsonPath('data.repeatMinutes', 15)
            ->assertJsonPath('data.severity', 'Normal')
            ->assertJsonPath('data.guestAlertActive', false)
            ->assertJsonPath('data.snapshotVersion', 1);

        $this->assertCount(0, $this->dispatchedPushes);

        $this->app['auth']->forgetGuards();

        $supportSnapshot = $this->getJson('/api/v1/monitors/'.$setup['monitor']->id.'/snapshot', [
            'Authorization' => 'Bearer '.$setup['supportToken'],
        ]);

        $supportSnapshot->assertOk()
            ->assertJsonPath('data.balanceCents', 35_000)
            ->assertJsonPath('data.limitCents', 30_000)
            ->assertJsonPath('data.repeatMinutes', 15)
            ->assertJsonPath('data.severity', 'Normal')
            ->assertJsonPath('data.guestAlertActive', false);

        $historyPage1 = $this->getJson(
            '/api/v1/monitors/'.$setup['monitor']->id.'/history?limit=2&filter=all',
            ['Authorization' => 'Bearer '.$setup['supportToken']],
        );

        $historyPage1->assertOk()
            ->assertJsonPath('data.hasMore', true)
            ->assertJsonPath('data.nextBeforeEntryId', 11)
            ->assertJsonCount(2, 'data.entries')
            ->assertJsonPath('data.entries.0.hostEntryId', 12)
            ->assertJsonPath('data.entries.0.kind', 'PixCredit')
            ->assertJsonPath('data.entries.1.hostEntryId', 11)
            ->assertJsonPath('data.entries.1.kind', 'TagDebit');

        $historyPage2 = $this->getJson(
            '/api/v1/monitors/'.$setup['monitor']->id.'/history?limit=2&beforeEntryId=11&filter=all',
            ['Authorization' => 'Bearer '.$setup['supportToken']],
        );

        $historyPage2->assertOk()
            ->assertJsonPath('data.hasMore', false)
            ->assertJsonPath('data.nextBeforeEntryId', null)
            ->assertJsonCount(1, 'data.entries')
            ->assertJsonPath('data.entries.0.hostEntryId', 10)
            ->assertJsonPath('data.entries.0.kind', 'Reference');

        $exitsOnly = $this->getJson(
            '/api/v1/monitors/'.$setup['monitor']->id.'/history?filter=exits',
            ['Authorization' => 'Bearer '.$setup['supportToken']],
        );

        $exitsOnly->assertOk()
            ->assertJsonCount(1, 'data.entries')
            ->assertJsonPath('data.entries.0.kind', 'TagDebit');
    }

    public function test_attention_alerts_host_only_on_first_emission_and_notifies_guest_from_second_emission_or_repeat_elapsed(): void
    {
        $this->travelTo('2026-11-25 14:00:00 UTC');
        $setup = $this->createHostAndSupport();
        $openedAtMs = (int) now('UTC')->getTimestampMs();

        $this->putJson(
            '/api/v1/installation/push-token',
            ['fcmToken' => 'support-fcm-token-1'],
            ['Authorization' => 'Bearer '.$setup['supportToken']],
        )->assertOk();

        $this->app['auth']->forgetGuards();

        // 1st emission at R$ 299,99 (limit R$ 300,00) => Attention, host-only, guestAlertActive = false
        $first = $this->putJson(
            '/api/v1/monitors/'.$setup['monitor']->id.'/snapshot',
            [
                'balanceCents' => 29_999,
                'limitCents' => 30_000,
                'repeatMinutes' => 15,
                'pauseMinutes' => 30,
                'needsReference' => false,
                'alertCycleId' => 'cycle-1',
                'alertOpenedAtMs' => $openedAtMs,
                'alertEmissionCount' => 1,
            ],
            ['Authorization' => 'Bearer '.$setup['hostToken']],
        );

        $first->assertOk()
            ->assertJsonPath('data.severity', 'Attention')
            ->assertJsonPath('data.guestAlertActive', false)
            ->assertJsonPath('data.guestAlertEligibleAtMs', $openedAtMs + 15 * 60_000);

        $this->assertCount(0, $this->dispatchedPushes);

        // If 15 minutes pass even without a 2nd Host push (e.g. Host paused locally),
        // Guest GET /snapshot automatically evaluates guestAlertActive = true!
        $this->travel(15)->minutes();
        $this->app['auth']->forgetGuards();

        $this->getJson('/api/v1/monitors/'.$setup['monitor']->id.'/snapshot', [
            'Authorization' => 'Bearer '.$setup['supportToken'],
        ])->assertOk()
            ->assertJsonPath('data.severity', 'Attention')
            ->assertJsonPath('data.guestAlertActive', true);

        // 2nd emission published by Host => guestAlertActive = true + FCM push dispatched!
        $this->app['auth']->forgetGuards();

        $second = $this->putJson(
            '/api/v1/monitors/'.$setup['monitor']->id.'/snapshot',
            [
                'balanceCents' => 29_999,
                'limitCents' => 30_000,
                'repeatMinutes' => 15,
                'pauseMinutes' => 30,
                'needsReference' => false,
                'alertCycleId' => 'cycle-1',
                'alertOpenedAtMs' => $openedAtMs,
                'alertEmissionCount' => 2,
            ],
            ['Authorization' => 'Bearer '.$setup['hostToken']],
        );

        $second->assertOk()
            ->assertJsonPath('data.severity', 'Attention')
            ->assertJsonPath('data.guestAlertActive', true);

        $this->assertCount(1, $this->dispatchedPushes);
        $this->assertSame(['support-fcm-token-1'], $this->dispatchedPushes[0]['tokens']);
        $this->assertSame('alert_triggered', $this->dispatchedPushes[0]['event']->eventType);

        // 3rd emission repeats push
        $this->travel(15)->minutes();
        $this->putJson(
            '/api/v1/monitors/'.$setup['monitor']->id.'/snapshot',
            [
                'balanceCents' => 28_000,
                'limitCents' => 30_000,
                'repeatMinutes' => 15,
                'pauseMinutes' => 30,
                'needsReference' => false,
                'alertCycleId' => 'cycle-1',
                'alertOpenedAtMs' => $openedAtMs,
                'alertEmissionCount' => 3,
            ],
            ['Authorization' => 'Bearer '.$setup['hostToken']],
        )->assertOk();

        $this->assertCount(2, $this->dispatchedPushes);
        $this->assertSame('alert_repeated', $this->dispatchedPushes[1]['event']->eventType);

        // Recovery to Normal sends alert_cleared
        $this->putJson(
            '/api/v1/monitors/'.$setup['monitor']->id.'/snapshot',
            [
                'balanceCents' => 30_000,
                'limitCents' => 30_000,
                'repeatMinutes' => 15,
                'pauseMinutes' => 30,
                'needsReference' => false,
                'alertCycleId' => null,
                'alertOpenedAtMs' => null,
                'alertEmissionCount' => 0,
            ],
            ['Authorization' => 'Bearer '.$setup['hostToken']],
        )->assertOk()
            ->assertJsonPath('data.severity', 'Normal')
            ->assertJsonPath('data.guestAlertActive', false);

        $this->assertCount(3, $this->dispatchedPushes);
        $this->assertSame('alert_cleared', $this->dispatchedPushes[2]['event']->eventType);
    }

    public function test_critical_below_half_limit_notifies_guest_immediately_on_first_emission(): void
    {
        $this->travelTo('2026-11-25 14:00:00 UTC');
        $setup = $this->createHostAndSupport();
        $openedAtMs = (int) now('UTC')->getTimestampMs();

        $this->putJson(
            '/api/v1/installation/push-token',
            ['fcmToken' => 'support-fcm-critical'],
            ['Authorization' => 'Bearer '.$setup['supportToken']],
        )->assertOk();

        $this->app['auth']->forgetGuards();

        // Exact half (R$ 150,00 for limit R$ 300,00) is still Attention (not Critical)
        $half = $this->putJson(
            '/api/v1/monitors/'.$setup['monitor']->id.'/snapshot',
            [
                'balanceCents' => 15_000,
                'limitCents' => 30_000,
                'repeatMinutes' => 15,
                'pauseMinutes' => 30,
                'needsReference' => false,
                'alertCycleId' => 'cycle-half',
                'alertOpenedAtMs' => $openedAtMs,
                'alertEmissionCount' => 1,
            ],
            ['Authorization' => 'Bearer '.$setup['hostToken']],
        );

        $half->assertOk()
            ->assertJsonPath('data.severity', 'Attention')
            ->assertJsonPath('data.guestAlertActive', false);
        $this->assertCount(0, $this->dispatchedPushes);

        // Below half (R$ 149,99 for limit R$ 300,00) => Critical, immediate guestAlertActive + immediate push!
        $critical = $this->putJson(
            '/api/v1/monitors/'.$setup['monitor']->id.'/snapshot',
            [
                'balanceCents' => 14_999,
                'limitCents' => 30_000,
                'repeatMinutes' => 15,
                'pauseMinutes' => 30,
                'needsReference' => false,
                'alertCycleId' => 'cycle-half',
                'alertOpenedAtMs' => $openedAtMs,
                'alertEmissionCount' => 1,
            ],
            ['Authorization' => 'Bearer '.$setup['hostToken']],
        );

        $critical->assertOk()
            ->assertJsonPath('data.severity', 'Critical')
            ->assertJsonPath('data.guestAlertActive', true);

        $this->assertCount(1, $this->dispatchedPushes);
        $this->assertSame(['support-fcm-critical'], $this->dispatchedPushes[0]['tokens']);
        $this->assertSame('alert_escalated', $this->dispatchedPushes[0]['event']->eventType);
        $this->assertSame('Critical', $this->dispatchedPushes[0]['event']->severity->value);
    }

    public function test_authorization_boundaries_and_push_token_cleanup_on_revocation_and_invalid_token(): void
    {
        $this->travelTo('2026-11-25 14:00:00 UTC');
        $setup = $this->createHostAndSupport();
        $otherMonitor = Monitor::factory()->create(['host_generation' => 1]);

        // Support CANNOT publish snapshot (403)
        $this->putJson(
            '/api/v1/monitors/'.$setup['monitor']->id.'/snapshot',
            [
                'balanceCents' => 20_000,
                'limitCents' => 30_000,
                'repeatMinutes' => 15,
                'pauseMinutes' => 30,
                'needsReference' => false,
                'alertEmissionCount' => 0,
            ],
            ['Authorization' => 'Bearer '.$setup['supportToken']],
        )->assertForbidden();

        // Support CANNOT read foreign monitor snapshot or history (404)
        $this->getJson('/api/v1/monitors/'.$otherMonitor->id.'/snapshot', [
            'Authorization' => 'Bearer '.$setup['supportToken'],
        ])->assertNotFound();

        $this->getJson('/api/v1/monitors/'.$otherMonitor->id.'/history', [
            'Authorization' => 'Bearer '.$setup['supportToken'],
        ])->assertNotFound();

        // Pending installation CANNOT register push token (403)
        $pendingInstallation = Installation::factory()->create();
        $pendingToken = $pendingInstallation->createToken('pairing-pending', ['pairing:pending'])->plainTextToken;
        $this->app['auth']->forgetGuards();

        $this->putJson(
            '/api/v1/installation/push-token',
            ['fcmToken' => 'pending-token'],
            ['Authorization' => 'Bearer '.$pendingToken],
        )->assertForbidden();

        // Register token for support, then trigger invalid token cleanup
        $this->app['auth']->forgetGuards();
        $this->putJson(
            '/api/v1/installation/push-token',
            ['fcmToken' => 'stale-token-to-prune'],
            ['Authorization' => 'Bearer '.$setup['supportToken']],
        )->assertOk();

        $this->invalidTokensToReturn = ['stale-token-to-prune'];
        $this->app['auth']->forgetGuards();

        $this->putJson(
            '/api/v1/monitors/'.$setup['monitor']->id.'/snapshot',
            [
                'balanceCents' => 10_000,
                'limitCents' => 30_000,
                'repeatMinutes' => 15,
                'pauseMinutes' => 30,
                'needsReference' => false,
                'alertCycleId' => 'cycle-crit',
                'alertOpenedAtMs' => (int) now('UTC')->getTimestampMs(),
                'alertEmissionCount' => 1,
            ],
            ['Authorization' => 'Bearer '.$setup['hostToken']],
        )->assertOk();

        $this->assertDatabaseMissing('installation_push_tokens', [
            'installation_id' => $setup['supportInstallation']->id,
        ]);

        // Re-register token, then revoke support => push token deleted immediately
        $this->invalidTokensToReturn = [];
        $this->app['auth']->forgetGuards();
        $this->putJson(
            '/api/v1/installation/push-token',
            ['fcmToken' => 'support-token-before-revoke'],
            ['Authorization' => 'Bearer '.$setup['supportToken']],
        )->assertOk();

        $this->assertDatabaseHas('installation_push_tokens', [
            'installation_id' => $setup['supportInstallation']->id,
        ]);

        $this->app['auth']->forgetGuards();
        $this->delete(
            '/api/v1/monitors/'.$setup['monitor']->id.'/supports/'.$setup['supportMembership']->id,
            headers: [
                'Authorization' => 'Bearer '.$setup['hostToken'],
                'Accept' => 'application/json',
            ],
        )->assertNoContent();

        $this->assertDatabaseMissing('installation_push_tokens', [
            'installation_id' => $setup['supportInstallation']->id,
        ]);

        // Unknown monitor UUID format returns 404 for host
        $this->app['auth']->forgetGuards();
        $this->getJson('/api/v1/monitors/'.(string) Str::uuid().'/snapshot', [
            'Authorization' => 'Bearer '.$setup['hostToken'],
        ])->assertNotFound();
    }

    /**
     * @return array{
     *     monitor: Monitor,
     *     hostInstallation: Installation,
     *     hostMembership: MonitorMembership,
     *     hostToken: string,
     *     supportInstallation: Installation,
     *     supportMembership: MonitorMembership,
     *     supportToken: string
     * }
     */
    private function createHostAndSupport(): array
    {
        $monitor = Monitor::factory()->create(['host_generation' => 1]);
        $hostInstallation = Installation::factory()->create(['label' => 'Host Phone']);
        $hostMembership = MonitorMembership::factory()
            ->host()
            ->for($monitor)
            ->for($hostInstallation)
            ->create(['generation' => 1]);
        $hostToken = $hostInstallation->createToken('host-installation', ['host:monitor'])->plainTextToken;

        $supportInstallation = Installation::factory()->create(['label' => 'Guest Phone']);
        $supportMembership = MonitorMembership::factory()
            ->for($monitor)
            ->for($supportInstallation)
            ->create([
                'role' => AccessRole::Support,
                'generation' => null,
            ]);
        $supportToken = $supportInstallation->createToken('pairing-pending', ['pairing:pending'])->plainTextToken;

        return compact(
            'monitor',
            'hostInstallation',
            'hostMembership',
            'hostToken',
            'supportInstallation',
            'supportMembership',
            'supportToken',
        );
    }
}
