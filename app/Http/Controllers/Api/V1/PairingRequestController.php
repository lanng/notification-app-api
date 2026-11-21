<?php

namespace App\Http\Controllers\Api\V1;

use App\Http\Controllers\Controller;
use App\Http\Requests\Api\V1\RedeemInvitationRequest;
use App\Support\AccessAndPairing\AccessAndPairing;
use App\Support\AccessAndPairing\AccessContext;
use App\Support\AccessAndPairing\AccessFailure;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

final class PairingRequestController extends Controller
{
    public function store(
        RedeemInvitationRequest $request,
        AccessAndPairing $accessAndPairing,
    ): JsonResponse {
        $payload = $request->validatedPayload();

        return response()->json([
            'data' => $accessAndPairing->redeemInvitation(
                $payload['invitationSecret'],
                $payload['installationLabel'],
            ),
        ], 201);
    }

    public function showCurrent(
        Request $request,
        AccessAndPairing $accessAndPairing,
    ): JsonResponse {
        $context = $request->attributes->get(AccessContext::REQUEST_ATTRIBUTE);

        if (! $context instanceof AccessContext) {
            throw new AccessFailure(401, 'access_unauthenticated', 'A credencial não é válida.');
        }

        return response()->json([
            'data' => $accessAndPairing->pollCurrentPairingRequest($context),
        ]);
    }
}
