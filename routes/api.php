<?php

use App\Http\Controllers\Api\V1\HostActivationController;
use App\Http\Controllers\Api\V1\InstallationController;
use App\Http\Controllers\Api\V1\InvitationController;
use App\Http\Controllers\Api\V1\OwnerMonitorController;
use App\Http\Controllers\Api\V1\PairingRequestController;
use App\Http\Middleware\ApplyAccessRateLimit;
use App\Http\Middleware\RequireInstallation;
use App\Http\Middleware\VerifyOwnerIdentity;
use Illuminate\Http\JsonResponse;
use Illuminate\Support\Facades\Route;

Route::get('/health', function (): JsonResponse {
    return response()->json([
        'status' => 'ok',
    ]);
})->name('api.health');

Route::get('/v1/owner/monitor', [OwnerMonitorController::class, 'show'])
    ->middleware([
        'throttle:ap5.owner.ip',
        VerifyOwnerIdentity::class,
        ApplyAccessRateLimit::class.':ap5.owner.identity',
    ])
    ->name('api.v1.owner.monitor');

Route::get('/v1/installation', [InstallationController::class, 'show'])
    ->middleware(['auth:sanctum', RequireInstallation::class])
    ->name('api.v1.installation.show');

Route::post('/v1/owner/host-activations', [HostActivationController::class, 'store'])
    ->middleware([
        'throttle:ap5.owner.ip',
        'v1.json',
        VerifyOwnerIdentity::class,
        ApplyAccessRateLimit::class.':ap5.owner.identity',
    ])
    ->name('api.v1.owner.host-activations.store');

Route::post('/v1/monitors/{monitor}/invitations', [InvitationController::class, 'store'])
    ->middleware([
        'auth:sanctum',
        RequireInstallation::class,
        ApplyAccessRateLimit::class.':ap5.invitation.issue',
        'v1.json',
    ])
    ->name('api.v1.monitors.invitations.store');

Route::get('/v1/monitors/{monitor}/invitations', [InvitationController::class, 'index'])
    ->middleware(['auth:sanctum', RequireInstallation::class])
    ->name('api.v1.monitors.invitations.index');

Route::delete('/v1/monitors/{monitor}/invitations/{invitation}', [InvitationController::class, 'destroy'])
    ->middleware(['auth:sanctum', RequireInstallation::class, 'v1.json'])
    ->name('api.v1.monitors.invitations.destroy');

Route::post('/v1/pairing-requests', [PairingRequestController::class, 'store'])
    ->middleware([
        'throttle:ap5.redeem.ip',
        'v1.json',
        ApplyAccessRateLimit::class.':ap5.redeem.secret',
    ])
    ->name('api.v1.pairing-requests.store');

Route::get('/v1/pairing-requests/current', [PairingRequestController::class, 'showCurrent'])
    ->middleware([
        'auth:sanctum',
        RequireInstallation::class,
        ApplyAccessRateLimit::class.':ap5.pairing.poll',
    ])
    ->name('api.v1.pairing-requests.current');
