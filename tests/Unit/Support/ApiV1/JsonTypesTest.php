<?php

namespace Tests\Unit\Support\ApiV1;

use App\Support\ApiV1\ApiProblem;
use App\Support\ApiV1\JsonTypes;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use stdClass;

class JsonTypesTest extends TestCase
{
    private const string FIELD = 'amount';

    public static function nativeIntegerValues(): array
    {
        return [
            'zero' => [0],
            'negative one' => [-1],
            'native minimum' => [PHP_INT_MIN],
            'native maximum' => [PHP_INT_MAX],
        ];
    }

    public static function nonNegativeIntegerValues(): array
    {
        return [
            'zero' => [0],
            'positive' => [1],
        ];
    }

    public static function nonIntegerValues(): array
    {
        return [
            'false' => [false],
            'true' => [true],
            'float' => [1.0],
            'numeric string' => ['1'],
            'null' => [null],
        ];
    }

    public static function invalidStringValues(): array
    {
        return [
            'empty string' => [''],
            'over default maximum' => [str_repeat('a', 129)],
            'integer' => [7],
            'boolean' => [false],
            'float' => [1.0],
            'null' => [null],
        ];
    }

    public static function booleanValues(): array
    {
        return [
            'false' => [false],
            'true' => [true],
        ];
    }

    public static function nonBooleanValues(): array
    {
        return [
            'zero' => [0],
            'one' => [1],
            'false string' => ['false'],
            'null' => [null],
        ];
    }

    public static function invalidDecimalStrings(): array
    {
        return [
            'plus sign' => ['+1'],
            'negative sign' => ['-1'],
            'decimal point' => ['1.0'],
            'exponent' => ['1e3'],
            'unicode digit' => ['١'],
            'trailing newline' => ["1\n"],
            'leading space' => [' 1'],
            'trailing space' => ['1 '],
            'empty string' => [''],
        ];
    }

    public static function overflowingDecimalStrings(): array
    {
        return [
            'one above native maximum' => ['9223372036854775808'],
            'nineteen nines' => ['9999999999999999999'],
            'padded overflow' => ['000009223372036854775808'],
            'twenty digit overflow' => ['10000000000000000000'],
        ];
    }

    public static function nonStringDecimalValues(): array
    {
        return [
            'integer' => [1],
            'boolean' => [true],
            'null' => [null],
        ];
    }

    #[DataProvider('nativeIntegerValues')]
    public function test_require_int64_returns_native_integer_values_unchanged(int $value): void
    {
        $result = JsonTypes::requireInt64($value, self::FIELD);

        $this->assertSame($value, $result);
    }

    #[DataProvider('nonNegativeIntegerValues')]
    public function test_require_int64_returns_non_negative_values_when_required(int $value): void
    {
        $result = JsonTypes::requireInt64($value, self::FIELD, true);

        $this->assertSame($value, $result);
    }

    #[DataProvider('nonIntegerValues')]
    public function test_require_int64_rejects_values_that_are_not_native_integers(mixed $value): void
    {
        $this->assertInvalidPayload(
            fn () => JsonTypes::requireInt64($value, self::FIELD),
            self::FIELD,
            $value,
        );
    }

    public function test_require_int64_rejects_arrays_and_objects(): void
    {
        foreach ([[], new stdClass] as $value) {
            $this->assertInvalidPayload(
                fn () => JsonTypes::requireInt64($value, self::FIELD),
                self::FIELD,
                $value,
            );
        }
    }

    public function test_require_int64_rejects_negative_values_when_non_negative_is_required(): void
    {
        $this->assertInvalidPayload(
            fn () => JsonTypes::requireInt64(-1, self::FIELD, true),
            self::FIELD,
            -1,
        );
    }

    public function test_require_int64_rejects_json_numbers_above_the_native_integer_range(): void
    {
        $value = json_decode('9223372036854775808', flags: JSON_THROW_ON_ERROR);

        $this->assertIsFloat($value);
        $this->assertInvalidPayload(
            fn () => JsonTypes::requireInt64($value, self::FIELD),
            self::FIELD,
            $value,
        );
    }

    public function test_require_string_returns_the_original_nonempty_string_without_trimming(): void
    {
        $value = "  id \n";

        $result = JsonTypes::requireString($value, 'id');

        $this->assertSame($value, $result);
    }

    public function test_require_string_accepts_the_default_maximum_character_count(): void
    {
        $value = str_repeat('a', 128);

        $result = JsonTypes::requireString($value, 'id');

        $this->assertSame($value, $result);
    }

    public function test_require_string_counts_utf8_characters_instead_of_bytes(): void
    {
        $value = 'José';

        $result = JsonTypes::requireString($value, 'id', 4);

        $this->assertSame($value, $result);
    }

    public function test_require_string_counts_utf8_characters_independently_of_internal_encoding(): void
    {
        $previousEncoding = mb_internal_encoding();
        $result = null;

        try {
            mb_internal_encoding('ISO-8859-1');

            try {
                $result = JsonTypes::requireString('José', 'id', 4);
            } catch (ApiProblem) {
            }
        } finally {
            mb_internal_encoding($previousEncoding);
        }

        $this->assertSame('José', $result);
        $this->assertSame($previousEncoding, mb_internal_encoding());
    }

    #[DataProvider('invalidStringValues')]
    public function test_require_string_rejects_empty_overlong_and_non_string_values(mixed $value): void
    {
        $this->assertInvalidPayload(
            fn () => JsonTypes::requireString($value, 'id'),
            'id',
            $value,
        );
    }

    public function test_require_string_enforces_a_custom_maximum_character_count(): void
    {
        $this->assertSame('abc', JsonTypes::requireString('abc', 'id', 3));

        $this->assertInvalidPayload(
            fn () => JsonTypes::requireString('abcd', 'id', 3),
            'id',
            'abcd',
        );
    }

    public function test_require_string_rejects_arrays_and_objects(): void
    {
        foreach ([[], new stdClass] as $value) {
            $this->assertInvalidPayload(
                fn () => JsonTypes::requireString($value, 'id'),
                'id',
                $value,
            );
        }
    }

    #[DataProvider('booleanValues')]
    public function test_require_boolean_returns_native_boolean_values_unchanged(bool $value): void
    {
        $result = JsonTypes::requireBoolean($value, self::FIELD);

        $this->assertSame($value, $result);
    }

    #[DataProvider('nonBooleanValues')]
    public function test_require_boolean_rejects_values_that_are_not_booleans(mixed $value): void
    {
        $this->assertInvalidPayload(
            fn () => JsonTypes::requireBoolean($value, self::FIELD),
            self::FIELD,
            $value,
        );
    }

    public function test_require_boolean_rejects_arrays_and_objects(): void
    {
        foreach ([[], new stdClass] as $value) {
            $this->assertInvalidPayload(
                fn () => JsonTypes::requireBoolean($value, self::FIELD),
                self::FIELD,
                $value,
            );
        }
    }

    public function test_require_decimal_string_preserves_padded_values_and_accepts_native_maximum(): void
    {
        foreach ([
            '0',
            '000',
            '001',
            '9223372036854775807',
            '0009223372036854775807',
            '0000000000000000000000001',
        ] as $value) {
            $this->assertSame($value, JsonTypes::requireDecimalString($value, self::FIELD));
        }
    }

    public function test_require_decimal_string_accepts_canonical_zero_and_positive_values(): void
    {
        $this->assertSame('0', JsonTypes::requireDecimalString('0', self::FIELD, canonical: true));
        $this->assertSame('1', JsonTypes::requireDecimalString('1', self::FIELD, positive: true));
    }

    public function test_require_decimal_string_rejects_padded_values_when_canonical_is_required(): void
    {
        foreach (['001', '000'] as $value) {
            $this->assertInvalidPayload(
                fn () => JsonTypes::requireDecimalString($value, self::FIELD, canonical: true),
                self::FIELD,
                $value,
            );
        }
    }

    public function test_require_decimal_string_rejects_zero_spellings_when_positive_is_required(): void
    {
        foreach (['0', '000'] as $value) {
            $this->assertInvalidPayload(
                fn () => JsonTypes::requireDecimalString($value, self::FIELD, positive: true),
                self::FIELD,
                $value,
            );
        }
    }

    #[DataProvider('overflowingDecimalStrings')]
    public function test_require_decimal_string_rejects_values_above_native_integer_maximum(string $value): void
    {
        $this->assertInvalidPayload(
            fn () => JsonTypes::requireDecimalString($value, self::FIELD),
            self::FIELD,
            $value,
        );
    }

    #[DataProvider('invalidDecimalStrings')]
    public function test_require_decimal_string_rejects_values_outside_the_ascii_digit_format(string $value): void
    {
        $this->assertInvalidPayload(
            fn () => JsonTypes::requireDecimalString($value, self::FIELD),
            self::FIELD,
            $value,
        );
    }

    #[DataProvider('nonStringDecimalValues')]
    public function test_require_decimal_string_rejects_non_string_values(mixed $value): void
    {
        $this->assertInvalidPayload(
            fn () => JsonTypes::requireDecimalString($value, self::FIELD),
            self::FIELD,
            $value,
        );
    }

    public function test_require_decimal_string_rejects_array_and_object_values(): void
    {
        foreach ([[], new stdClass] as $value) {
            $this->assertInvalidPayload(
                fn () => JsonTypes::requireDecimalString($value, self::FIELD),
                self::FIELD,
                $value,
            );
        }
    }

    private function assertInvalidPayload(callable $operation, string $field, mixed $rejectedValue): void
    {
        try {
            $operation();
            self::fail('An invalid value must be rejected.');
        } catch (ApiProblem $problem) {
            $expectedProblem = ApiProblem::invalidPayload($field);

            $this->assertSame(422, $problem->status);
            $this->assertSame('invalid_payload', $problem->errorCode);
            $this->assertSame('Os dados enviados são inválidos.', $problem->safeMessage);
            $this->assertSame($expectedProblem->getMessage(), $problem->getMessage());
            $this->assertSame($expectedProblem->errors, $problem->errors);
            $this->assertSame([], $problem->headers);

            $expectedDetails = $expectedProblem->getMessage().$expectedProblem->safeMessage.serialize($expectedProblem->errors);

            if (
                is_string($rejectedValue)
                && $rejectedValue !== ''
                && ! str_contains($expectedDetails, $rejectedValue)
            ) {
                $details = $problem->getMessage().$problem->safeMessage.serialize($problem->errors);

                $this->assertStringNotContainsString($rejectedValue, $details);
            }
        }
    }
}
