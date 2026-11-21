<?php

namespace Tests\Support;

use App\Support\AccessAndPairing\AccessFailure;
use App\Support\AccessAndPairing\OwnerIdentityVerifier;
use App\Support\AccessAndPairing\VerifiedOwnerIdentity;
use Illuminate\Http\Request;

final class FakeOwnerIdentityVerifier implements OwnerIdentityVerifier
{
    public const TEST_BEARER_TOKEN = 'test-owner-fixture';

    public function __construct(private readonly VerifiedOwnerIdentity $identity) {}

    public function verify(Request $request): VerifiedOwnerIdentity
    {
        if ($request->bearerToken() !== self::TEST_BEARER_TOKEN) {
            throw new AccessFailure(401, 'access_unauthenticated', 'Autenticação necessária.');
        }

        return $this->identity;
    }
}
