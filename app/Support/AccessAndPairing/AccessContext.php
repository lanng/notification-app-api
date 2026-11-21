<?php

namespace App\Support\AccessAndPairing;

final readonly class AccessContext
{
    public const REQUEST_ATTRIBUTE = 'access.context';

    public function __construct(
        public string $installationId,
        public int $accessTokenId,
    ) {}
}
