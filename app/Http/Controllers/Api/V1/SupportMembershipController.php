<?php

namespace App\Http\Controllers\Api\V1;

use App\Http\Controllers\Controller;
use App\Http\Requests\Api\V1\NoPayloadRequest;
use App\Support\AccessAndPairing\AccessAndPairing;
use App\Support\AccessAndPairing\AccessContext;
use App\Support\AccessAndPairing\AccessFailure;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Str;

final class SupportMembershipController extends Controller
{
    public function index(
        Request $request,
        string $monitor,
        AccessAndPairing $accessAndPairing,
    ): JsonResponse {
        $context = $request->attributes->get(AccessContext::REQUEST_ATTRIBUTE);

        if (! $context instanceof AccessContext) {
            throw new AccessFailure(401, 'access_unauthenticated', 'A credencial não é válida.');
        }

        return response()->json([
            'data' => $accessAndPairing->listSupportMemberships($context, $monitor),
        ]);
    }

    public function destroy(
        NoPayloadRequest $request,
        string $monitor,
        string $membership,
        AccessAndPairing $accessAndPairing,
    ): JsonResponse {
        $context = $this->accessContext($request);
        $accessAndPairing->preflightHostMonitor($context, $monitor);

        if (! Str::isUuid($membership)) {
            throw new AccessFailure(404, 'resource_not_found', 'Recurso não encontrado.');
        }

        $request->validatedPayload();
        $accessAndPairing->revokeSupportMembership($context, $monitor, $membership);

        return response()->json(status: 204);
    }

    private function accessContext(Request $request): AccessContext
    {
        $context = $request->attributes->get(AccessContext::REQUEST_ATTRIBUTE);

        if (! $context instanceof AccessContext) {
            throw new AccessFailure(401, 'access_unauthenticated', 'A credencial não é válida.');
        }

        return $context;
    }
}
