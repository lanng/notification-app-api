<?php

namespace App\Support\SharedMonitor;

final class NullSharedAlertPushDispatcher implements SharedAlertPushDispatcher
{
    /**
     * @param  list<string>  $fcmTokens
     * @return list<string>
     */
    public function dispatchToTokens(array $fcmTokens, SharedAlertPushEvent $event): array
    {
        return [];
    }
}
