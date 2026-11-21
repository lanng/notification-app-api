<?php

namespace App\Http\Controllers\Api\V1;

use App\Http\Controllers\Controller;
use App\Support\AccessAndPairing\AccessAndPairing;
use App\Support\AccessAndPairing\AccessFailure;
use App\Support\AccessAndPairing\VerifiedOwnerIdentity;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

final class OwnerMonitorController extends Controller
{
    public function show(Request $request, AccessAndPairing $accessAndPairing): JsonResponse
    {
        $identity = $request->attributes->get('access.owner_identity');

        if (! $identity instanceof VerifiedOwnerIdentity) {
            throw new AccessFailure(401, 'access_unauthenticated', 'Autenticação necessária.');
        }

        return response()->json([
            'data' => $accessAndPairing->discoverOwnerMonitor($identity),
        ]);
    }
}
