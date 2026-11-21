<?php

namespace App\Support\AccessAndPairing;

use Illuminate\Http\Request;

final class DisabledOwnerIdentityVerifier implements OwnerIdentityVerifier
{
    public function verify(Request $request): VerifiedOwnerIdentity
    {
        throw new AccessFailure(
            503,
            'identity_verification_unavailable',
            'Verificação de identidade indisponível.',
        );
    }
}
