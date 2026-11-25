<?php

namespace App\Enums;

enum SharedAlertSeverity: string
{
    case Unknown = 'Unknown';
    case Normal = 'Normal';
    case Attention = 'Attention';
    case Critical = 'Critical';

    public static function classify(?int $balanceCents, int $limitCents): self
    {
        if ($balanceCents === null || $limitCents <= 0) {
            return self::Unknown;
        }

        if ($balanceCents >= $limitCents) {
            return self::Normal;
        }

        $criticalThresholdCents = intdiv($limitCents, 2) + ($limitCents % 2);

        if ($balanceCents < $criticalThresholdCents) {
            return self::Critical;
        }

        return self::Attention;
    }
}
