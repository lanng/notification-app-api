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

final class MonitorPairingRequestController extends Controller
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
            'data' => $accessAndPairing->listPairingRequests($context, $monitor),
        ]);
    }

    public function approve(
        NoPayloadRequest $request,
        string $monitor,
        string $pairingRequest,
        AccessAndPairing $accessAndPairing,
    ): JsonResponse {
        $context = $this->accessContext($request);
        $accessAndPairing->preflightHostMonitor($context, $monitor);

        if (! Str::isUuid($pairingRequest)) {
            throw new AccessFailure(404, 'resource_not_found', 'Recurso não encontrado.');
        }

        $request->validatedPayload();

        return response()->json([
            'data' => $accessAndPairing->approvePairingRequest(
                $context,
                $monitor,
                $pairingRequest,
            ),
        ]);
    }

    public function reject(
        NoPayloadRequest $request,
        string $monitor,
        string $pairingRequest,
        AccessAndPairing $accessAndPairing,
    ): JsonResponse {
        $context = $this->accessContext($request);
        $accessAndPairing->preflightHostMonitor($context, $monitor);

        if (! Str::isUuid($pairingRequest)) {
            throw new AccessFailure(404, 'resource_not_found', 'Recurso não encontrado.');
        }

        $request->validatedPayload();

        return response()->json([
            'data' => $accessAndPairing->rejectPairingRequest(
                $context,
                $monitor,
                $pairingRequest,
            ),
        ]);
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
