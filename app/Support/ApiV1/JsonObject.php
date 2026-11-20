<?php

namespace App\Support\ApiV1;

use JsonException;
use stdClass;

class JsonObject
{
    private function __construct(private readonly stdClass $value) {}

    public static function decode(string $body): self
    {
        try {
            $value = json_decode($body, flags: JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            throw ApiProblem::malformedJson();
        }

        if (! $value instanceof stdClass) {
            throw ApiProblem::invalidPayload();
        }

        return new self($value);
    }

    /**
     * @param  list<string>  $allowed
     * @param  list<string>  $required
     * @return array<string, mixed>
     */
    public function only(array $allowed, array $required = []): array
    {
        $properties = get_object_vars($this->value);
        $present = array_keys($properties);

        if (array_diff($present, $allowed) !== [] || array_diff($required, $present) !== []) {
            throw ApiProblem::invalidPayload();
        }

        $result = [];

        foreach ($allowed as $key) {
            if (array_key_exists($key, $properties)) {
                $result[$key] = $properties[$key];
            }
        }

        return $result;
    }
}
