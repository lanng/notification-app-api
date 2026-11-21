<?php

namespace App\Support\AccessAndPairing;

use RuntimeException;

final class AccessFailure extends RuntimeException
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
}
