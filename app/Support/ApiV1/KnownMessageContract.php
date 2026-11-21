<?php

namespace App\Support\ApiV1;

use JsonException;

class KnownMessageContract
{
    private const array SHARED_STATE_KEYS = [
        'schemaVersion',
        'messageType',
        'monitorId',
        'hostGeneration',
        'stateVersion',
        'balanceCents',
        'limitCents',
        'needsReview',
        'lastFinancialUpdateAtMs',
        'lastHostContactAtMs',
        'cycleId',
        'episodeId',
        'severity',
    ];

    private const array ALERT_OCCURRENCE_KEYS = [
        'schemaVersion',
        'messageType',
        'monitorId',
        'hostGeneration',
        'stateVersion',
        'cycleId',
        'episodeId',
        'recipientId',
        'dueNumber',
        'severity',
        'scheduledAtMs',
        'expiresAtMs',
    ];

    private const array ALLOWED_KEYS = [
        'schemaVersion',
        'messageType',
        'monitorId',
        'hostGeneration',
        'stateVersion',
        'balanceCents',
        'limitCents',
        'needsReview',
        'lastFinancialUpdateAtMs',
        'lastHostContactAtMs',
        'cycleId',
        'episodeId',
        'severity',
        'recipientId',
        'dueNumber',
        'scheduledAtMs',
        'expiresAtMs',
    ];

    /**
     * @return array<string, mixed>
     */
    public static function decode(string $body): array
    {
        $payload = JsonObject::decode($body)->only(self::ALLOWED_KEYS, ['messageType']);

        return self::validatePayload($payload);
    }

    /**
     * @param  array<string, mixed>  $payload
     */
    public static function encode(array $payload): string
    {
        self::validatePayload($payload);

        try {
            return json_encode(
                $payload,
                flags: JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE,
            );
        } catch (JsonException) {
            throw ApiProblem::invalidPayload();
        }
    }

    /**
     * @param  array<string, mixed>  $payload
     * @return array<string, mixed>
     */
    private static function validatePayload(array $payload): array
    {
        $messageType = $payload['messageType'] ?? null;

        if (! is_string($messageType) || ! in_array($messageType, ['sharedState', 'alertOccurrence'], true)) {
            throw ApiProblem::invalidPayload();
        }

        $requiredKeys = $messageType === 'sharedState'
            ? self::SHARED_STATE_KEYS
            : self::ALERT_OCCURRENCE_KEYS;

        self::requireExactKeys($payload, $requiredKeys);

        $schemaVersion = JsonTypes::requireInt64($payload['schemaVersion'], 'schemaVersion');

        if ($schemaVersion !== 1) {
            throw ApiProblem::invalidPayload('schemaVersion');
        }

        JsonTypes::requireString($payload['monitorId'], 'monitorId');
        JsonTypes::requireDecimalString($payload['hostGeneration'], 'hostGeneration');
        JsonTypes::requireDecimalString($payload['stateVersion'], 'stateVersion');
        JsonTypes::requireString($payload['cycleId'], 'cycleId');
        JsonTypes::requireString($payload['episodeId'], 'episodeId');
        JsonTypes::requireString($payload['severity'], 'severity', 32);

        if ($messageType === 'sharedState') {
            JsonTypes::requireInt64($payload['balanceCents'], 'balanceCents');
            JsonTypes::requireInt64($payload['limitCents'], 'limitCents', nonNegative: true);
            JsonTypes::requireBoolean($payload['needsReview'], 'needsReview');
            JsonTypes::requireInt64($payload['lastFinancialUpdateAtMs'], 'lastFinancialUpdateAtMs', nonNegative: true);
            JsonTypes::requireInt64($payload['lastHostContactAtMs'], 'lastHostContactAtMs', nonNegative: true);
        } else {
            JsonTypes::requireString($payload['recipientId'], 'recipientId');
            JsonTypes::requireDecimalString($payload['dueNumber'], 'dueNumber', positive: true);
            JsonTypes::requireInt64($payload['scheduledAtMs'], 'scheduledAtMs', nonNegative: true);
            JsonTypes::requireInt64($payload['expiresAtMs'], 'expiresAtMs', nonNegative: true);

            if ($payload['expiresAtMs'] <= $payload['scheduledAtMs']) {
                throw ApiProblem::invalidPayload('expiresAtMs');
            }
        }

        $validatedPayload = [];

        foreach ($requiredKeys as $key) {
            $validatedPayload[$key] = $payload[$key];
        }

        return $validatedPayload;
    }

    /**
     * @param  array<string, mixed>  $payload
     * @param  list<string>  $requiredKeys
     */
    private static function requireExactKeys(array $payload, array $requiredKeys): void
    {
        foreach ($payload as $key => $_value) {
            if (! is_string($key) || ! in_array($key, $requiredKeys, true)) {
                throw ApiProblem::invalidPayload();
            }
        }

        foreach ($requiredKeys as $key) {
            if (! array_key_exists($key, $payload)) {
                throw ApiProblem::invalidPayload();
            }
        }
    }
}
