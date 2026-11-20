<?php

namespace Tests\Unit\Support\ApiV1;

use App\Support\ApiV1\ApiProblem;
use PHPUnit\Framework\TestCase;
use RuntimeException;

class ApiProblemTest extends TestCase
{
    public function test_constructor_preserves_problem_fields_and_safe_exception_message(): void
    {
        $errors = ['name' => ['O campo é inválido.']];
        $headers = ['Retry-After' => '10'];
        $safeMessage = 'Os dados enviados são inválidos.';
        $problem = new ApiProblem(422, 'invalid_payload', $safeMessage, $errors, $headers);

        $this->assertInstanceOf(RuntimeException::class, $problem);
        $this->assertSame(422, $problem->status);
        $this->assertSame('invalid_payload', $problem->errorCode);
        $this->assertSame($safeMessage, $problem->safeMessage);
        $this->assertSame($errors, $problem->errors);
        $this->assertSame($headers, $problem->headers);
        $this->assertSame($safeMessage, $problem->getMessage());
        $this->assertSame(0, $problem->getCode());
    }

    public function test_malformed_json_factory_returns_safe_400_problem(): void
    {
        $problem = ApiProblem::malformedJson();

        $this->assertSame(400, $problem->status);
        $this->assertSame('malformed_json', $problem->errorCode);
        $this->assertSame('O corpo JSON é inválido.', $problem->safeMessage);
        $this->assertSame([], $problem->errors);
        $this->assertSame([], $problem->headers);
    }

    public function test_unsupported_media_type_factory_returns_safe_415_problem(): void
    {
        $problem = ApiProblem::unsupportedMediaType();

        $this->assertSame(415, $problem->status);
        $this->assertSame('unsupported_media_type', $problem->errorCode);
        $this->assertSame('O tipo de conteúdo não é suportado.', $problem->safeMessage);
        $this->assertSame([], $problem->errors);
        $this->assertSame([], $problem->headers);
    }

    public function test_invalid_payload_factory_returns_generic_422_problem_without_a_field(): void
    {
        $problem = ApiProblem::invalidPayload();

        $this->assertSame(422, $problem->status);
        $this->assertSame('invalid_payload', $problem->errorCode);
        $this->assertSame('Os dados enviados são inválidos.', $problem->safeMessage);
        $this->assertSame([], $problem->errors);
        $this->assertSame([], $problem->headers);
    }

    public function test_invalid_payload_factory_returns_safe_field_error(): void
    {
        $problem = ApiProblem::invalidPayload('name');

        $this->assertSame(422, $problem->status);
        $this->assertSame('invalid_payload', $problem->errorCode);
        $this->assertSame('Os dados enviados são inválidos.', $problem->safeMessage);
        $this->assertSame(['name' => ['O valor informado é inválido.']], $problem->errors);
        $this->assertSame([], $problem->headers);
    }
}
