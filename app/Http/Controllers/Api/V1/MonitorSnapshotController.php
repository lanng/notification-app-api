<?php

namespace App\Http\Controllers\Api\V1;

use App\Http\Controllers\Controller;
use App\Http\Requests\Api\V1\PublishMonitorSnapshotRequest;
use App\Support\AccessAndPairing\AccessContext;
use App\Support\AccessAndPairing\AccessFailure;
use App\Support\SharedMonitor\SharedMonitorSync;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

final class MonitorSnapshotController extends Controller
{
    public function upsert(
        PublishMonitorSnapshotRequest $request,
        string $monitor,
        SharedMonitorSync $sharedMonitorSync,
    ): JsonResponse {
        $context = $this->accessContext($request);
        $payload = $request->validatedPayload();

        return response()->json([
            'data' => $sharedMonitorSync->publishHostSnapshot($context, $monitor, $payload),
        ]);
    }

    public function show(
        Request $request,
        string $monitor,
        SharedMonitorSync $sharedMonitorSync,
    ): JsonResponse {
        $context = $this->accessContext($request);

        return response()->json([
            'data' => $sharedMonitorSync->showMonitorSnapshot($context, $monitor),
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
