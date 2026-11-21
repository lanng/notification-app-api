<?php

namespace App\Http\Controllers\Api\V1;

use App\Http\Controllers\Controller;
use App\Support\AccessAndPairing\AccessAndPairing;
use App\Support\AccessAndPairing\AccessContext;
use App\Support\AccessAndPairing\AccessFailure;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

final class InstallationController extends Controller
{
    public function show(Request $request, AccessAndPairing $accessAndPairing): JsonResponse
    {
        $context = $request->attributes->get(AccessContext::REQUEST_ATTRIBUTE);

        if (! $context instanceof AccessContext) {
            throw new AccessFailure(401, 'access_unauthenticated', 'A credencial não é válida.');
        }

        return response()->json([
            'data' => $accessAndPairing->discoverCurrentInstallationAccess($context->installationId),
        ]);
    }
}
