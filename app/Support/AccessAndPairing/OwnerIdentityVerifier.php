<?php

namespace App\Support\AccessAndPairing;

use Illuminate\Http\Request;

interface OwnerIdentityVerifier
{
    /**
     * Verify a Firebase identity token, including issuer, audience, expiry,
     * revocation, and the trusted Google provider before returning its claims.
     */
    public function verify(Request $request): VerifiedOwnerIdentity;
}
