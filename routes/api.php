<?php

use App\Http\Controllers\Api\V1\HostActivationController;
use App\Http\Controllers\Api\V1\OwnerMonitorController;
use App\Http\Middleware\VerifyOwnerIdentity;
use Illuminate\Http\JsonResponse;
use Illuminate\Support\Facades\Route;

Route::get('/health', function (): JsonResponse {
    return response()->json([
        'status' => 'ok',
    ]);
})->name('api.health');

Route::get('/v1/owner/monitor', [OwnerMonitorController::class, 'show'])
    ->middleware(VerifyOwnerIdentity::class)
    ->name('api.v1.owner.monitor');

Route::post('/v1/owner/host-activations', [HostActivationController::class, 'store'])
    ->middleware(['v1.json', VerifyOwnerIdentity::class])
    ->name('api.v1.owner.host-activations.store');
