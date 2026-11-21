<?php

namespace App\Http\Controllers\Api\V1;

use App\Http\Controllers\Controller;
use App\Http\Requests\Api\V1\ActivateHostRequest;
use App\Support\AccessAndPairing\AccessAndPairing;
use App\Support\AccessAndPairing\AccessFailure;
use App\Support\AccessAndPairing\VerifiedOwnerIdentity;
use Illuminate\Http\JsonResponse;

final class HostActivationController extends Controller
{
    public function store(
        ActivateHostRequest $request,
        AccessAndPairing $accessAndPairing,
    ): JsonResponse {
        $identity = $request->attributes->get('access.owner_identity');

        if (! $identity instanceof VerifiedOwnerIdentity) {
            throw new AccessFailure(401, 'access_unauthenticated', 'Autenticação necessária.');
        }

        $payload = $request->validatedPayload();
        $activation = $accessAndPairing->activateHost(
            $identity,
            $payload['confirmation'],
            $payload['expectedGeneration'],
        );

        return response()->json(
            ['data' => $activation['data']],
            $activation['firstActivation'] ? 201 : 200,
        );
    }
}
