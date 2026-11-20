<?php

namespace Tests\Unit\Support\ApiV1;

use App\Support\ApiV1\ApiProblem;
use App\Support\ApiV1\JsonObject;
use PHPUnit\Framework\TestCase;

class JsonObjectTest extends TestCase
{
    public function test_only_returns_present_values_in_allowlist_order_without_coercion(): void
    {
        $object = JsonObject::decode(
            '{"number":7,"text":"7","boolean":false,"zero":0,"nothing":null,"nested":{"enabled":true},"items":[null,3]}',
        );

        $properties = $object->only(
            ['items', 'nested', 'nothing', 'zero', 'boolean', 'text', 'number'],
            ['number', 'nothing'],
        );

        $this->assertSame(['items', 'nested', 'nothing', 'zero', 'boolean', 'text', 'number'], array_keys($properties));
        $this->assertSame([null, 3], $properties['items']);
        $this->assertInstanceOf(\stdClass::class, $properties['nested']);
        $this->assertSame(['enabled' => true], get_object_vars($properties['nested']));
        $this->assertNull($properties['nothing']);
        $this->assertSame(0, $properties['zero']);
        $this->assertSame(false, $properties['boolean']);
        $this->assertSame('7', $properties['text']);
        $this->assertSame(7, $properties['number']);
    }

    public function test_malformed_json_returns_safe_400_problem(): void
    {
        $problems = [];

        foreach (['', '{"name":'] as $body) {
            try {
                JsonObject::decode($body);
                self::fail('Malformed JSON must be rejected.');
            } catch (ApiProblem $problem) {
                $problems[] = [
                    $problem->status,
                    $problem->errorCode,
                    $problem->safeMessage,
                    $problem->errors,
                ];
            }
        }

        $this->assertSame([
            [400, 'malformed_json', 'O corpo JSON é inválido.', []],
            [400, 'malformed_json', 'O corpo JSON é inválido.', []],
        ], $problems);
    }

    public function test_non_object_json_roots_return_generic_422_problems(): void
    {
        $problems = [];

        foreach (['[]', 'null', '7', '"text"', 'true'] as $body) {
            try {
                JsonObject::decode($body);
                self::fail('A non-object JSON root must be rejected.');
            } catch (ApiProblem $problem) {
                $problems[] = [
                    $problem->status,
                    $problem->errorCode,
                    $problem->safeMessage,
                    $problem->errors,
                ];
            }
        }

        $this->assertSame([
            [422, 'invalid_payload', 'Os dados enviados são inválidos.', []],
            [422, 'invalid_payload', 'Os dados enviados são inválidos.', []],
            [422, 'invalid_payload', 'Os dados enviados são inválidos.', []],
            [422, 'invalid_payload', 'Os dados enviados são inválidos.', []],
            [422, 'invalid_payload', 'Os dados enviados são inválidos.', []],
        ], $problems);
    }

    public function test_unknown_keys_return_generic_422_without_echoing_submitted_data(): void
    {
        try {
            JsonObject::decode('{"name":"Ana","secret":"do-not-echo"}')->only(['name']);
            self::fail('Unknown keys must be rejected.');
        } catch (ApiProblem $problem) {
            $this->assertSame(422, $problem->status);
            $this->assertSame('invalid_payload', $problem->errorCode);
            $this->assertSame('Os dados enviados são inválidos.', $problem->safeMessage);
            $this->assertSame([], $problem->errors);

            $details = $problem->getMessage().$problem->safeMessage.serialize($problem->errors);

            foreach (['Ana', 'do-not-echo', 'secret'] as $sensitiveValue) {
                $this->assertStringNotContainsString($sensitiveValue, $details);
            }
        }
    }

    public function test_missing_required_keys_return_generic_422_problem(): void
    {
        try {
            JsonObject::decode('{}')->only(['name'], ['name']);
            self::fail('Missing required keys must be rejected.');
        } catch (ApiProblem $problem) {
            $this->assertSame(422, $problem->status);
            $this->assertSame('invalid_payload', $problem->errorCode);
            $this->assertSame('Os dados enviados são inválidos.', $problem->safeMessage);
            $this->assertSame([], $problem->errors);
        }
    }

    public function test_empty_object_with_empty_allowlist_returns_empty_array(): void
    {
        $properties = JsonObject::decode('{}')->only([]);

        $this->assertSame([], $properties);
    }

    public function test_missing_optional_allowed_keys_are_excluded(): void
    {
        $properties = JsonObject::decode('{"name":"Ana"}')->only(['name', 'nickname']);

        $this->assertSame(['name' => 'Ana'], $properties);
    }

    public function test_present_null_required_value_is_preserved(): void
    {
        $properties = JsonObject::decode('{"name":null}')->only(['name'], ['name']);

        $this->assertSame(['name' => null], $properties);
    }
}
