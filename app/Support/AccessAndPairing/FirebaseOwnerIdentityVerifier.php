<?php

namespace App\Support\AccessAndPairing;

use Illuminate\Http\Request;
use Kreait\Firebase\Util;

final class FirebaseOwnerIdentityVerifier implements OwnerIdentityVerifier
{
    public function __construct(
        private readonly mixed $firebaseProjectId,
        private readonly mixed $firebaseUid,
        private readonly mixed $credentialsPath,
        private readonly ?FirebaseVerificationClient $verificationClient = null,
    ) {}

    public function verify(Request $request): VerifiedOwnerIdentity
    {
        $idToken = $request->bearerToken();

        if (! is_string($idToken) || $idToken === '') {
            throw new AccessFailure(
                401,
                'access_unauthenticated',
                'Autenticação necessária.',
            );
        }

        if (
            ! is_string($this->firebaseProjectId)
            || $this->firebaseProjectId === ''
            || ! is_string($this->firebaseUid)
            || $this->firebaseUid === ''
            || ! is_string($this->credentialsPath)
            || $this->credentialsPath === ''
            || $this->verificationClient === null
            || Util::authEmulatorHost() !== null
        ) {
            throw new AccessFailure(
                503,
                'identity_verification_unavailable',
                'Verificação de identidade indisponível.',
            );
        }

        return $this->verificationClient->verify($idToken);
    }
}
