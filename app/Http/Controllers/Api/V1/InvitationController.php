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

final class InvitationController extends Controller
{
    public function store(
        NoPayloadRequest $request,
        string $monitor,
        AccessAndPairing $accessAndPairing,
    ): JsonResponse {
        $context = $this->accessContext($request);
        $accessAndPairing->preflightHostMonitor($context, $monitor);
        $request->validatedPayload();

        return response()->json([
            'data' => $accessAndPairing->issueInvitation($context, $monitor),
        ], 201);
    }

    public function index(
        Request $request,
        string $monitor,
        AccessAndPairing $accessAndPairing,
    ): JsonResponse {
        $context = $this->accessContext($request);

        return response()->json([
            'data' => $accessAndPairing->listInvitations($context, $monitor),
        ]);
    }

    public function destroy(
        NoPayloadRequest $request,
        string $monitor,
        string $invitation,
        AccessAndPairing $accessAndPairing,
    ): JsonResponse {
        $context = $this->accessContext($request);
        $accessAndPairing->preflightHostMonitor($context, $monitor);

        if (! Str::isUuid($invitation)) {
            throw new AccessFailure(404, 'resource_not_found', 'Recurso não encontrado.');
        }

        $request->validatedPayload();
        $accessAndPairing->cancelInvitation($context, $monitor, $invitation);

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
