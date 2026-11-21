<?php

namespace Tests\Unit\Support\ApiV1;

use App\Support\ApiV1\ApiProblem;
use App\Support\ApiV1\KnownMessageContract;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use stdClass;

class KnownMessageContractTest extends TestCase
{
    public static function invalidSchemaVersions(): array
    {
        return [
            'string' => ['1'],
            'float' => [1.0],
            'boolean' => [true],
            'null' => [null],
            'unsupported integer' => [2],
        ];
    }

    public static function invalidNativeIntegerValues(): array
    {
        return [
            'string' => ['28000'],
            'float' => [28000.0],
            'boolean' => [true],
            'null' => [null],
        ];
    }

    public static function invalidTimestampValues(): array
    {
        return [
            'string' => ['1000'],
            'float' => [1000.0],
            'boolean' => [true],
            'null' => [null],
        ];
    }

    public static function invalidBooleanValues(): array
    {
        return [
            'integer' => [0],
            'string' => ['false'],
            'null' => [null],
        ];
    }

    public static function invalidSeverityValues(): array
    {
        return [
            'empty' => [''],
            'overlong' => [str_repeat('x', 33)],
            'integer' => [7],
            'null' => [null],
        ];
    }

    public static function invalidMessageTypeValues(): array
    {
        return [
            'integer' => [7],
            'boolean' => [true],
            'null' => [null],
            'array' => [[]],
        ];
    }

    public static function invalidVersionDecimalValues(): array
    {
        return [
            'positive overflow' => ['9223372036854775808'],
            'negative overflow' => ['-9223372036854775809'],
        ];
    }

    public static function negativeVersionValues(): array
    {
        return [
            'negative one' => ['-1'],
            'negative zero' => ['-0'],
            'negative padded value' => ['-00012'],
        ];
    }

    public static function invalidDecimalStrings(): array
    {
        return [
            'negative sign for due number' => ['-1'],
            'decimal point' => ['1.0'],
            'exponent' => ['1e3'],
            'space' => [' 1'],
            'empty' => [''],
        ];
    }

    public static function nativeFloatPayloadFields(): array
    {
        return [
            'schema version' => ['schemaVersion', 1.0],
            'balance' => ['balanceCents', 28000.0],
            'timestamp' => ['lastFinancialUpdateAtMs', 1000.0],
        ];
    }

    public static function identifierFields(): array
    {
        return [
            'monitor ID' => ['sharedState', 'monitorId'],
            'cycle ID' => ['sharedState', 'cycleId'],
            'episode ID' => ['sharedState', 'episodeId'],
            'recipient ID' => ['alertOccurrence', 'recipientId'],
        ];
    }

    public static function nonStringIdentifierValues(): array
    {
        return [
            'integer' => [7],
            'boolean' => [false],
            'null' => [null],
            'array' => [[]],
            'object' => [new stdClass],
        ];
    }

    public static function timestampFields(): array
    {
        return [
            'financial update' => ['sharedState', 'lastFinancialUpdateAtMs'],
            'host contact' => ['sharedState', 'lastHostContactAtMs'],
            'scheduled' => ['alertOccurrence', 'scheduledAtMs'],
            'expires' => ['alertOccurrence', 'expiresAtMs'],
        ];
    }

    public function test_fixtures_decode_to_the_independent_shared_and_occurrence_payloads(): void
    {
        $sharedPath = $this->fixturePath('shared-attention.json');
        $occurrencePath = $this->fixturePath('critical-occurrence.json');

        $this->assertSame(
            '79511eff479eb1d82cf6b22a07e43635ade51d9e0880e0805f76550582c941b6',
            hash_file('sha256', $sharedPath),
        );
        $this->assertSame(
            '3a8d49446da65c85abb6789b7ceffafe1842596ca3dac4d509df785b8c058b64',
            hash_file('sha256', $occurrencePath),
        );

        $sharedBody = file_get_contents($sharedPath);
        $occurrenceBody = file_get_contents($occurrencePath);

        $this->assertIsString($sharedBody);
        $this->assertIsString($occurrenceBody);

        $sharedPayload = KnownMessageContract::decode($sharedBody);
        $occurrencePayload = KnownMessageContract::decode($occurrenceBody);

        $this->assertSame([
            'schemaVersion' => 1,
            'messageType' => 'sharedState',
            'monitorId' => 'synthetic-monitor',
            'hostGeneration' => '1',
            'stateVersion' => '12',
            'balanceCents' => 28000,
            'limitCents' => 30000,
            'needsReview' => false,
            'lastFinancialUpdateAtMs' => 1000,
            'lastHostContactAtMs' => 2000,
            'cycleId' => 'synthetic-cycle',
            'episodeId' => 'synthetic-attention',
            'severity' => 'attention',
        ], $sharedPayload);
        $this->assertSame([
            'schemaVersion' => 1,
            'messageType' => 'alertOccurrence',
            'monitorId' => 'synthetic-monitor',
            'hostGeneration' => '1',
            'stateVersion' => '13',
            'cycleId' => 'synthetic-cycle',
            'episodeId' => 'synthetic-critical',
            'recipientId' => 'synthetic-support',
            'dueNumber' => '1',
            'severity' => 'critical',
            'scheduledAtMs' => 600000,
            'expiresAtMs' => 900000,
        ], $occurrencePayload);

        $this->assertSame($sharedPayload, KnownMessageContract::decode(KnownMessageContract::encode($sharedPayload)));
        $this->assertSame(
            $occurrencePayload,
            KnownMessageContract::decode(KnownMessageContract::encode($occurrencePayload)),
        );
    }

    public function test_encode_and_decode_preserve_padded_decimal_strings_and_unrecognized_severity(): void
    {
        $payload = $this->occurrencePayload();
        $payload['hostGeneration'] = '00001';
        $payload['stateVersion'] = '00012';
        $payload['dueNumber'] = '0007';
        $payload['severity'] = 'future-level';

        $result = KnownMessageContract::decode(KnownMessageContract::encode($payload));

        $this->assertSame($payload, $result);

        $payload['hostGeneration'] = '000';
        $payload['stateVersion'] = '0';

        $this->assertSame($payload, KnownMessageContract::decode(KnownMessageContract::encode($payload)));
    }

    public function test_native_integer_boundaries_and_negative_balance_are_preserved(): void
    {
        $payload = $this->sharedStatePayload();
        $payload['hostGeneration'] = '0';
        $payload['stateVersion'] = '0';
        $payload['balanceCents'] = PHP_INT_MIN;
        $payload['limitCents'] = PHP_INT_MAX;
        $payload['lastFinancialUpdateAtMs'] = PHP_INT_MAX - 1;
        $payload['lastHostContactAtMs'] = PHP_INT_MAX;

        $result = KnownMessageContract::decode(KnownMessageContract::encode($payload));

        $this->assertSame($payload, $result);

        $occurrence = $this->occurrencePayload();
        $occurrence['hostGeneration'] = (string) PHP_INT_MAX;
        $occurrence['stateVersion'] = '0';
        $occurrence['dueNumber'] = (string) PHP_INT_MAX;
        $occurrence['scheduledAtMs'] = PHP_INT_MAX - 1;
        $occurrence['expiresAtMs'] = PHP_INT_MAX;

        $this->assertSame($occurrence, KnownMessageContract::decode(KnownMessageContract::encode($occurrence)));
    }

    #[DataProvider('invalidSchemaVersions')]
    public function test_decode_returns_422_for_schema_versions_that_are_not_native_integer_one(mixed $value): void
    {
        $payload = $this->sharedStatePayload();
        $payload['schemaVersion'] = $value;

        $this->assertInvalidPayload(fn () => KnownMessageContract::decode($this->jsonBody($payload)), 'schemaVersion');
    }

    #[DataProvider('nativeFloatPayloadFields')]
    public function test_encode_rejects_native_floats_before_json_serialization(string $field, float $value): void
    {
        $payload = $this->sharedStatePayload();
        $payload[$field] = $value;

        $this->assertInvalidPayload(fn () => KnownMessageContract::encode($payload), $field);
    }

    public function test_decode_accepts_negative_balance_but_rejects_negative_limit(): void
    {
        $payload = $this->sharedStatePayload();
        $payload['balanceCents'] = -1;

        $this->assertSame($payload, KnownMessageContract::decode($this->jsonBody($payload)));

        $payload['limitCents'] = -1;

        $this->assertInvalidPayload(fn () => KnownMessageContract::decode($this->jsonBody($payload)), 'limitCents');
    }

    #[DataProvider('invalidNativeIntegerValues')]
    public function test_decode_rejects_non_integer_balance_and_limit_values(mixed $value): void
    {
        foreach (['balanceCents', 'limitCents'] as $field) {
            $payload = $this->sharedStatePayload();
            $payload[$field] = $value;

            $this->assertInvalidPayload(
                fn () => KnownMessageContract::decode($this->jsonBody($payload)),
                $field,
            );
        }
    }

    public function test_decode_rejects_json_integer_numbers_outside_the_native_int64_range(): void
    {
        foreach (['balanceCents', 'lastFinancialUpdateAtMs'] as $field) {
            $payload = $this->sharedStatePayload();
            $body = str_replace(
                '"'.$field.'":'.($field === 'balanceCents' ? '28000' : '1000'),
                '"'.$field.'":9223372036854775808',
                $this->jsonBody($payload),
            );

            $this->assertInvalidPayload(fn () => KnownMessageContract::decode($body), $field);
        }
    }

    #[DataProvider('invalidVersionDecimalValues')]
    public function test_decode_rejects_invalid_or_overflowing_generation_and_version_strings(string $value): void
    {
        foreach (['hostGeneration', 'stateVersion'] as $field) {
            $payload = $this->sharedStatePayload();
            $payload[$field] = $value;

            $this->assertInvalidPayload(
                fn () => KnownMessageContract::decode($this->jsonBody($payload)),
                $field,
            );
        }
    }

    #[DataProvider('negativeVersionValues')]
    public function test_decode_and_encode_reject_negative_generation_and_version_strings_for_both_messages(
        string $value,
    ): void {
        foreach (['sharedState', 'alertOccurrence'] as $messageType) {
            foreach (['hostGeneration', 'stateVersion'] as $field) {
                $payload = $messageType === 'sharedState' ? $this->sharedStatePayload() : $this->occurrencePayload();
                $payload[$field] = $value;

                $this->assertInvalidPayload(
                    fn () => KnownMessageContract::decode($this->jsonBody($payload)),
                    $field,
                );
                $this->assertInvalidPayload(
                    fn () => KnownMessageContract::encode($payload),
                    $field,
                );
            }
        }
    }

    #[DataProvider('invalidDecimalStrings')]
    public function test_decode_rejects_due_numbers_that_are_not_positive_ascii_decimal_strings(string $value): void
    {
        $payload = $this->occurrencePayload();
        $payload['dueNumber'] = $value;

        $this->assertInvalidPayload(
            fn () => KnownMessageContract::decode($this->jsonBody($payload)),
            'dueNumber',
        );
    }

    public function test_decode_rejects_zero_and_overflowing_due_numbers(): void
    {
        foreach (['0', '000', '9223372036854775808'] as $value) {
            $payload = $this->occurrencePayload();
            $payload['dueNumber'] = $value;

            $this->assertInvalidPayload(
                fn () => KnownMessageContract::decode($this->jsonBody($payload)),
                'dueNumber',
            );
        }
    }

    #[DataProvider('invalidBooleanValues')]
    public function test_decode_rejects_needs_review_values_that_are_not_booleans(mixed $value): void
    {
        $payload = $this->sharedStatePayload();
        $payload['needsReview'] = $value;

        $this->assertInvalidPayload(fn () => KnownMessageContract::decode($this->jsonBody($payload)), 'needsReview');
    }

    #[DataProvider('invalidSeverityValues')]
    public function test_decode_rejects_severity_values_that_are_empty_overlong_or_not_strings(mixed $value): void
    {
        foreach (['sharedState', 'alertOccurrence'] as $messageType) {
            $payload = $messageType === 'sharedState' ? $this->sharedStatePayload() : $this->occurrencePayload();
            $payload['severity'] = $value;

            $this->assertInvalidPayload(
                fn () => KnownMessageContract::decode($this->jsonBody($payload)),
                'severity',
            );
        }
    }

    #[DataProvider('identifierFields')]
    public function test_decode_rejects_empty_and_overlong_identifiers(string $messageType, string $field): void
    {
        foreach (['', str_repeat('x', 129)] as $value) {
            $payload = $messageType === 'sharedState' ? $this->sharedStatePayload() : $this->occurrencePayload();
            $payload[$field] = $value;

            $this->assertInvalidPayload(
                fn () => KnownMessageContract::decode($this->jsonBody($payload)),
                $field,
            );
        }
    }

    #[DataProvider('nonStringIdentifierValues')]
    public function test_decode_rejects_identifiers_that_are_not_strings(mixed $value): void
    {
        foreach (self::identifierFields() as [$messageType, $field]) {
            $payload = $messageType === 'sharedState' ? $this->sharedStatePayload() : $this->occurrencePayload();
            $payload[$field] = $value;

            $this->assertInvalidPayload(
                fn () => KnownMessageContract::decode($this->jsonBody($payload)),
                $field,
            );
        }
    }

    public function test_decode_accepts_identifiers_at_the_character_limit(): void
    {
        $payload = $this->sharedStatePayload();
        $payload['monitorId'] = str_repeat('x', 128);

        $this->assertSame($payload, KnownMessageContract::decode($this->jsonBody($payload)));
    }

    #[DataProvider('timestampFields')]
    public function test_decode_rejects_negative_timestamps(string $messageType, string $field): void
    {
        $payload = $messageType === 'sharedState' ? $this->sharedStatePayload() : $this->occurrencePayload();
        $payload[$field] = -1;

        $this->assertInvalidPayload(fn () => KnownMessageContract::decode($this->jsonBody($payload)), $field);
    }

    #[DataProvider('invalidTimestampValues')]
    public function test_decode_rejects_timestamps_that_are_not_native_integers(mixed $value): void
    {
        foreach (self::timestampFields() as [$messageType, $field]) {
            $payload = $messageType === 'sharedState' ? $this->sharedStatePayload() : $this->occurrencePayload();
            $payload[$field] = $value;

            $this->assertInvalidPayload(
                fn () => KnownMessageContract::decode($this->jsonBody($payload)),
                $field,
            );
        }
    }

    public function test_decode_rejects_equal_or_earlier_occurrence_expiry(): void
    {
        foreach ([600000, 599999] as $expiresAtMs) {
            $payload = $this->occurrencePayload();
            $payload['expiresAtMs'] = $expiresAtMs;

            $this->assertInvalidPayload(
                fn () => KnownMessageContract::decode($this->jsonBody($payload)),
                'expiresAtMs',
            );
        }
    }

    public function test_decode_rejects_occurrence_fields_from_shared_state_and_transport_extras(): void
    {
        $payload = $this->sharedStatePayload();
        $payload['recipientId'] = 'synthetic-support';

        $this->assertGenericInvalidPayload(fn () => KnownMessageContract::decode($this->jsonBody($payload)));

        $payload = $this->occurrencePayload();
        $payload['balanceCents'] = 28000;

        $this->assertGenericInvalidPayload(fn () => KnownMessageContract::decode($this->jsonBody($payload)));

        $payload = $this->occurrencePayload();
        $payload['diagnosticMetadata'] = ['trace' => 'do-not-accept'];

        $this->assertGenericInvalidPayload(fn () => KnownMessageContract::decode($this->jsonBody($payload)));
    }

    #[DataProvider('invalidMessageTypeValues')]
    public function test_decode_returns_generic_422_for_message_types_that_are_not_strings(mixed $value): void
    {
        $payload = $this->sharedStatePayload();
        $payload['messageType'] = $value;

        $this->assertGenericInvalidPayload(fn () => KnownMessageContract::decode($this->jsonBody($payload)));
    }

    public function test_unknown_message_type_and_missing_fields_return_generic_422_problems(): void
    {
        $payload = $this->sharedStatePayload();
        $payload['messageType'] = 'future-financial-message';

        $this->assertGenericInvalidPayload(fn () => KnownMessageContract::decode($this->jsonBody($payload)));

        $payload = $this->sharedStatePayload();
        unset($payload['monitorId']);

        $this->assertGenericInvalidPayload(fn () => KnownMessageContract::decode($this->jsonBody($payload)));

        $payload = $this->occurrencePayload();
        unset($payload['recipientId']);

        $this->assertGenericInvalidPayload(fn () => KnownMessageContract::decode($this->jsonBody($payload)));
    }

    public function test_unknown_fields_return_generic_422_without_echoing_submitted_or_legitimate_data(): void
    {
        $payload = $this->sharedStatePayload();
        $payload['firebaseToken'] = 'do-not-echo';

        try {
            KnownMessageContract::decode($this->jsonBody($payload));
            self::fail('Unknown fields must be rejected.');
        } catch (ApiProblem $problem) {
            $this->assertSame(422, $problem->status);
            $this->assertSame('invalid_payload', $problem->errorCode);
            $this->assertSame('Os dados enviados são inválidos.', $problem->safeMessage);
            $this->assertSame([], $problem->errors);

            $details = $problem->getMessage().$problem->safeMessage.serialize($problem->errors);

            foreach (['firebaseToken', 'do-not-echo', 'synthetic-monitor'] as $sensitiveValue) {
                $this->assertStringNotContainsString($sensitiveValue, $details);
            }
        }
    }

    public function test_decode_returns_400_for_malformed_json_and_422_for_non_object_roots(): void
    {
        foreach (['', '{"messageType":'] as $body) {
            $this->assertApiProblem(
                fn () => KnownMessageContract::decode($body),
                400,
                'malformed_json',
            );
        }

        foreach (['[]', 'null', '7', '"text"', 'true'] as $body) {
            $this->assertApiProblem(
                fn () => KnownMessageContract::decode($body),
                422,
                'invalid_payload',
            );
        }
    }

    private function assertGenericInvalidPayload(callable $operation): void
    {
        $this->assertApiProblem($operation, 422, 'invalid_payload');
    }

    private function assertInvalidPayload(callable $operation, string $field): void
    {
        $this->assertApiProblem(
            $operation,
            422,
            'invalid_payload',
            [$field => ['O valor informado é inválido.']],
            'Os dados enviados são inválidos.',
        );
    }

    /**
     * @param  array<string, list<string>>  $errors
     */
    private function assertApiProblem(
        callable $operation,
        int $status,
        string $errorCode,
        array $errors = [],
        ?string $safeMessage = null,
    ): void {
        try {
            $operation();
            self::fail('The payload must be rejected.');
        } catch (ApiProblem $problem) {
            $this->assertSame($status, $problem->status);
            $this->assertSame($errorCode, $problem->errorCode);
            $this->assertSame($errors, $problem->errors);

            if ($safeMessage !== null) {
                $this->assertSame($safeMessage, $problem->safeMessage);
            }
        }
    }

    /**
     * @param  array<string, mixed>  $payload
     */
    private function jsonBody(array $payload): string
    {
        return json_encode($payload, JSON_THROW_ON_ERROR | JSON_PRESERVE_ZERO_FRACTION);
    }

    private function fixturePath(string $name): string
    {
        return dirname(__DIR__, 3).'/Fixtures/Remote/V1/'.$name;
    }

    /**
     * @return array<string, int|string|bool>
     */
    private function sharedStatePayload(): array
    {
        return [
            'schemaVersion' => 1,
            'messageType' => 'sharedState',
            'monitorId' => 'synthetic-monitor',
            'hostGeneration' => '1',
            'stateVersion' => '12',
            'balanceCents' => 28000,
            'limitCents' => 30000,
            'needsReview' => false,
            'lastFinancialUpdateAtMs' => 1000,
            'lastHostContactAtMs' => 2000,
            'cycleId' => 'synthetic-cycle',
            'episodeId' => 'synthetic-attention',
            'severity' => 'attention',
        ];
    }

    /**
     * @return array<string, int|string>
     */
    private function occurrencePayload(): array
    {
        return [
            'schemaVersion' => 1,
            'messageType' => 'alertOccurrence',
            'monitorId' => 'synthetic-monitor',
            'hostGeneration' => '1',
            'stateVersion' => '13',
            'cycleId' => 'synthetic-cycle',
            'episodeId' => 'synthetic-critical',
            'recipientId' => 'synthetic-support',
            'dueNumber' => '1',
            'severity' => 'critical',
            'scheduledAtMs' => 600000,
            'expiresAtMs' => 900000,
        ];
    }
}
