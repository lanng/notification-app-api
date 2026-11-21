<?php

namespace App\Support\ApiV1;

class JsonTypes
{
    public static function requireInt64(mixed $value, string $field, bool $nonNegative = false): int
    {
        if (! is_int($value) || ($nonNegative && $value < 0)) {
            throw ApiProblem::invalidPayload($field);
        }

        return $value;
    }

    public static function requireString(mixed $value, string $field, int $max = 128): string
    {
        if (! is_string($value) || $value === '' || mb_strlen($value, 'UTF-8') > $max) {
            throw ApiProblem::invalidPayload($field);
        }

        return $value;
    }

    public static function requireBoolean(mixed $value, string $field): bool
    {
        if (! is_bool($value)) {
            throw ApiProblem::invalidPayload($field);
        }

        return $value;
    }

    public static function requireDecimalString(
        mixed $value,
        string $field,
        bool $canonical = false,
        bool $positive = false,
    ): string {
        if (! is_string($value) || preg_match('/\A[0-9]+\z/', $value) !== 1) {
            throw ApiProblem::invalidPayload($field);
        }

        $normalized = ltrim($value, '0');

        if ($normalized === '') {
            $normalized = '0';
        }

        $maximum = (string) PHP_INT_MAX;
        $normalizedLength = strlen($normalized);
        $maximumLength = strlen($maximum);

        if (
            $normalizedLength > $maximumLength
            || ($normalizedLength === $maximumLength && strcmp($normalized, $maximum) > 0)
            || ($canonical && $value !== $normalized)
            || ($positive && $normalized === '0')
        ) {
            throw ApiProblem::invalidPayload($field);
        }

        return $value;
    }
}
