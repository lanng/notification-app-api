<?php

namespace App\Support\ApiV1;

use RuntimeException;

class ApiProblem extends RuntimeException
{
    /**
     * @param  array<string, list<string>>  $errors
     * @param  array<string, string>  $headers
     */
    public function __construct(
        public readonly int $status,
        public readonly string $errorCode,
        public readonly string $safeMessage,
        public readonly array $errors = [],
        public readonly array $headers = [],
    ) {
        parent::__construct($safeMessage);
    }

    public static function malformedJson(): self
    {
        return new self(400, 'malformed_json', 'O corpo JSON é inválido.');
    }

    public static function unsupportedMediaType(): self
    {
        return new self(415, 'unsupported_media_type', 'O tipo de conteúdo não é suportado.');
    }

    public static function invalidPayload(?string $field = null): self
    {
        return new self(
            422,
            'invalid_payload',
            'Os dados enviados são inválidos.',
            $field === null ? [] : [$field => ['O valor informado é inválido.']],
        );
    }
}
