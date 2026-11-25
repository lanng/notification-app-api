<?php

namespace App\Support\SharedMonitor;

use Illuminate\Support\Facades\Log;
use Kreait\Firebase\Factory;
use Kreait\Firebase\Http\HttpClientOptions;
use Kreait\Firebase\Messaging\CloudMessage;
use Kreait\Firebase\Util;
use Throwable;

final class FirebaseMessagingPushDispatcher implements SharedAlertPushDispatcher
{
    public function __construct(
        private readonly string $projectId,
        private readonly string $credentialsPath,
    ) {}

    /**
     * @param  list<string>  $fcmTokens
     * @return list<string>
     */
    public function dispatchToTokens(array $fcmTokens, SharedAlertPushEvent $event): array
    {
        if ($fcmTokens === [] || Util::authEmulatorHost() !== null) {
            return [];
        }

        if (! is_file($this->credentialsPath) || ! is_readable($this->credentialsPath)) {
            Log::warning('Shared alert FCM dispatch skipped because credentials file is unavailable.');

            return [];
        }

        $connectTimeout = config('access_pairing.firebase.connect_timeout', 3.0);
        $timeout = config('access_pairing.firebase.timeout', 5.0);

        $httpOptions = HttpClientOptions::default()
            ->withConnectTimeout(is_numeric($connectTimeout) && $connectTimeout > 0 ? (float) $connectTimeout : 3.0)
            ->withTimeout(is_numeric($timeout) && $timeout > 0 ? (float) $timeout : 5.0)
            ->withGuzzleConfigOption('allow_redirects', false);

        try {
            $messaging = (new Factory)
                ->withProjectId($this->projectId)
                ->withHttpClientOptions($httpOptions)
                ->withServiceAccount($this->credentialsPath)
                ->createMessaging();

            $message = CloudMessage::new()
                ->withData($event->toFcmDataPayload())
                ->withAndroidConfig([
                    'priority' => 'high',
                    'ttl' => '900s',
                ]);

            $report = $messaging->sendMulticast($message, $fcmTokens);

            if ($report->hasFailures()) {
                Log::warning('Shared alert FCM multicast completed with partial failures.', [
                    'eventType' => $event->eventType,
                    'severity' => $event->severity->value,
                    'successCount' => $report->successes()->count(),
                    'failureCount' => $report->failures()->count(),
                ]);
            }

            return array_values(array_unique(array_merge(
                $report->unknownTokens(),
                $report->invalidTokens(),
            )));
        } catch (Throwable $exception) {
            Log::warning('Shared alert FCM dispatch failed.', [
                'eventType' => $event->eventType,
                'severity' => $event->severity->value,
                'exception' => $exception::class,
            ]);

            return [];
        }
    }
}
