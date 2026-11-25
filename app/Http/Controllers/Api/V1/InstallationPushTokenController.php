<?php

namespace App\Http\Controllers\Api\V1;

use App\Http\Controllers\Controller;
use App\Http\Requests\Api\V1\UpsertPushTokenRequest;
use App\Support\AccessAndPairing\AccessContext;
use App\Support\AccessAndPairing\AccessFailure;
use App\Support\SharedMonitor\SharedMonitorSync;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

final class InstallationPushTokenController extends Controller
{
    public function upsert(
        UpsertPushTokenRequest $request,
        SharedMonitorSync $sharedMonitorSync,
    ): JsonResponse {
        $context = $this->accessContext($request);
        $payload = $request->validatedPayload();

        return response()->json([
            'data' => $sharedMonitorSync->registerPushToken($context, $payload['fcmToken']),
        ]);
    }

    public function destroy(
        Request $request,
        SharedMonitorSync $sharedMonitorSync,
    ): JsonResponse {
        $context = $this->accessContext($request);
        $sharedMonitorSync->deletePushToken($context);

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
