<?php

namespace App\Support\SharedMonitor;

interface SharedAlertPushDispatcher
{
    /**
     * Dispatch a data-only alert event to active support FCM tokens.
     *
     * @param  list<string>  $fcmTokens
     * @return list<string> Invalid or unregistered tokens that should be removed.
     */
    public function dispatchToTokens(array $fcmTokens, SharedAlertPushEvent $event): array;
}
