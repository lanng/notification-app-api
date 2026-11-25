<?php

namespace App\Http\Requests\Api\V1;

use App\Enums\FinancialEntryKind;
use App\Support\ApiV1\ApiProblem;
use App\Support\ApiV1\JsonObject;
use App\Support\ApiV1\JsonTypes;
use Illuminate\Foundation\Http\FormRequest;
use stdClass;

final class PublishMonitorSnapshotRequest extends FormRequest
{
    private const array ALLOWED_REPEAT_MINUTES = [15, 30, 60];

    private const array ALLOWED_PAUSE_MINUTES = [15, 30, 60, 120];

    private const int MAX_ENTRIES_PER_SYNC = 100;

    public function authorize(): bool
    {
        return true;
    }

    /** @return array<string, never> */
    public function rules(): array
    {
        return [];
    }

    /**
     * @return array{
     *     balanceCents: ?int,
     *     limitCents: int,
     *     repeatMinutes: int,
     *     pauseMinutes: int,
     *     needsReference: bool,
     *     alertCycleId: ?string,
     *     alertOpenedAtMs: ?int,
     *     alertEmissionCount: int,
     *     lastObservedAtMs: ?int,
     *     referenceConfirmedAtMs: ?int,
     *     entries: list<array{
     *         hostEntryId: int,
     *         kind: FinancialEntryKind,
     *         amountCents: int,
     *         balanceAfterCents: int,
     *         recordedAtMs: int
     *     }>
     * }
     */
    public function validatedPayload(): array
    {
        $jsonObject = $this->attributes->get('v1.json');

        if (! $jsonObject instanceof JsonObject) {
            throw ApiProblem::invalidPayload();
        }

        $payload = $jsonObject->only(
            allowed: [
                'balanceCents',
                'limitCents',
                'repeatMinutes',
                'pauseMinutes',
                'needsReference',
                'alertCycleId',
                'alertOpenedAtMs',
                'alertEmissionCount',
                'lastObservedAtMs',
                'referenceConfirmedAtMs',
                'entries',
            ],
            required: [
                'limitCents',
                'repeatMinutes',
                'pauseMinutes',
                'needsReference',
                'alertEmissionCount',
            ],
        );

        $balanceCents = array_key_exists('balanceCents', $payload) && $payload['balanceCents'] !== null
            ? JsonTypes::requireInt64($payload['balanceCents'], 'balanceCents')
            : null;
        $limitCents = JsonTypes::requireInt64($payload['limitCents'], 'limitCents', nonNegative: true);

        if ($limitCents <= 0) {
            throw ApiProblem::invalidPayload('limitCents');
        }

        $repeatMinutes = JsonTypes::requireInt64($payload['repeatMinutes'], 'repeatMinutes', nonNegative: true);

        if (! in_array($repeatMinutes, self::ALLOWED_REPEAT_MINUTES, true)) {
            throw ApiProblem::invalidPayload('repeatMinutes');
        }

        $pauseMinutes = JsonTypes::requireInt64($payload['pauseMinutes'], 'pauseMinutes', nonNegative: true);

        if (! in_array($pauseMinutes, self::ALLOWED_PAUSE_MINUTES, true)) {
            throw ApiProblem::invalidPayload('pauseMinutes');
        }

        $needsReference = JsonTypes::requireBoolean($payload['needsReference'], 'needsReference');

        $alertCycleId = array_key_exists('alertCycleId', $payload) && $payload['alertCycleId'] !== null
            ? JsonTypes::requireString($payload['alertCycleId'], 'alertCycleId', max: 128)
            : null;

        $alertOpenedAtMs = array_key_exists('alertOpenedAtMs', $payload) && $payload['alertOpenedAtMs'] !== null
            ? JsonTypes::requireInt64($payload['alertOpenedAtMs'], 'alertOpenedAtMs', nonNegative: true)
            : null;

        $alertEmissionCount = JsonTypes::requireInt64(
            $payload['alertEmissionCount'],
            'alertEmissionCount',
            nonNegative: true,
        );

        if ($alertEmissionCount > 100_000) {
            throw ApiProblem::invalidPayload('alertEmissionCount');
        }

        $lastObservedAtMs = array_key_exists('lastObservedAtMs', $payload) && $payload['lastObservedAtMs'] !== null
            ? JsonTypes::requireInt64($payload['lastObservedAtMs'], 'lastObservedAtMs', nonNegative: true)
            : null;

        $referenceConfirmedAtMs = array_key_exists('referenceConfirmedAtMs', $payload)
            && $payload['referenceConfirmedAtMs'] !== null
            ? JsonTypes::requireInt64($payload['referenceConfirmedAtMs'], 'referenceConfirmedAtMs', nonNegative: true)
            : null;

        $entries = [];

        if (array_key_exists('entries', $payload)) {
            if (! is_array($payload['entries']) || ! array_is_list($payload['entries'])) {
                throw ApiProblem::invalidPayload('entries');
            }

            if (count($payload['entries']) > self::MAX_ENTRIES_PER_SYNC) {
                throw ApiProblem::invalidPayload('entries');
            }

            foreach ($payload['entries'] as $rawEntry) {
                if (! $rawEntry instanceof stdClass) {
                    throw ApiProblem::invalidPayload('entries');
                }

                $entryProps = get_object_vars($rawEntry);
                $allowedEntryKeys = ['hostEntryId', 'kind', 'amountCents', 'balanceAfterCents', 'recordedAtMs'];
                $presentKeys = array_keys($entryProps);

                if (
                    array_diff($presentKeys, $allowedEntryKeys) !== []
                    || array_diff($allowedEntryKeys, $presentKeys) !== []
                ) {
                    throw ApiProblem::invalidPayload('entries');
                }

                $hostEntryId = JsonTypes::requireInt64($entryProps['hostEntryId'], 'entries', nonNegative: true);

                if ($hostEntryId <= 0) {
                    throw ApiProblem::invalidPayload('entries');
                }

                $kindString = JsonTypes::requireString($entryProps['kind'], 'entries', max: 24);
                $kind = FinancialEntryKind::tryFrom($kindString);

                if ($kind === null) {
                    throw ApiProblem::invalidPayload('entries');
                }

                $amountCents = JsonTypes::requireInt64($entryProps['amountCents'], 'entries');
                $balanceAfterCents = JsonTypes::requireInt64($entryProps['balanceAfterCents'], 'entries');
                $recordedAtMs = JsonTypes::requireInt64($entryProps['recordedAtMs'], 'entries', nonNegative: true);

                $entries[] = [
                    'hostEntryId' => $hostEntryId,
                    'kind' => $kind,
                    'amountCents' => $amountCents,
                    'balanceAfterCents' => $balanceAfterCents,
                    'recordedAtMs' => $recordedAtMs,
                ];
            }
        }

        return [
            'balanceCents' => $balanceCents,
            'limitCents' => $limitCents,
            'repeatMinutes' => $repeatMinutes,
            'pauseMinutes' => $pauseMinutes,
            'needsReference' => $needsReference,
            'alertCycleId' => $alertCycleId,
            'alertOpenedAtMs' => $alertOpenedAtMs,
            'alertEmissionCount' => $alertEmissionCount,
            'lastObservedAtMs' => $lastObservedAtMs,
            'referenceConfirmedAtMs' => $referenceConfirmedAtMs,
            'entries' => $entries,
        ];
    }
}
