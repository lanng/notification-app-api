<?php

namespace App\Support\AccessAndPairing;

final readonly class VerifiedOwnerIdentity
{
    public function __construct(
        public string $firebaseProjectId,
        public string $firebaseUid,
        public string $provider,
        public int $authTime,
    ) {}
}
