<?php

use App\Http\Controllers\Api\V1\HostActivationController;
use App\Http\Controllers\Api\V1\InstallationController;
use App\Http\Controllers\Api\V1\InstallationPushTokenController;
use App\Http\Controllers\Api\V1\InvitationController;
use App\Http\Controllers\Api\V1\MonitorHistoryController;
use App\Http\Controllers\Api\V1\MonitorPairingRequestController;
use App\Http\Controllers\Api\V1\MonitorSnapshotController;
use App\Http\Controllers\Api\V1\OwnerMonitorController;
use App\Http\Controllers\Api\V1\PairingRequestController;
use App\Http\Controllers\Api\V1\SupportMembershipController;
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

Route::get('/v1/monitors/{monitor}/supports', [SupportMembershipController::class, 'index'])
    ->middleware(['auth:sanctum', RequireInstallation::class])
    ->name('api.v1.monitors.supports.index');

Route::get('/v1/monitors/{monitor}/pairing-requests', [MonitorPairingRequestController::class, 'index'])
    ->middleware(['auth:sanctum', RequireInstallation::class])
    ->name('api.v1.monitors.pairing-requests.index');

Route::post('/v1/monitors/{monitor}/pairing-requests/{pairingRequest}/approval', [MonitorPairingRequestController::class, 'approve'])
    ->middleware(['auth:sanctum', RequireInstallation::class, 'v1.json'])
    ->name('api.v1.monitors.pairing-requests.approve');

Route::post('/v1/monitors/{monitor}/pairing-requests/{pairingRequest}/rejection', [MonitorPairingRequestController::class, 'reject'])
    ->middleware(['auth:sanctum', RequireInstallation::class, 'v1.json'])
    ->name('api.v1.monitors.pairing-requests.reject');

Route::delete('/v1/monitors/{monitor}/supports/{membership}', [SupportMembershipController::class, 'destroy'])
    ->middleware(['auth:sanctum', RequireInstallation::class, 'v1.json'])
    ->name('api.v1.monitors.supports.destroy');

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

Route::put('/v1/monitors/{monitor}/snapshot', [MonitorSnapshotController::class, 'upsert'])
    ->middleware(['auth:sanctum', RequireInstallation::class, 'v1.json'])
    ->name('api.v1.monitors.snapshot.upsert');

Route::get('/v1/monitors/{monitor}/snapshot', [MonitorSnapshotController::class, 'show'])
    ->middleware(['auth:sanctum', RequireInstallation::class])
    ->name('api.v1.monitors.snapshot.show');

Route::get('/v1/monitors/{monitor}/history', [MonitorHistoryController::class, 'index'])
    ->middleware(['auth:sanctum', RequireInstallation::class])
    ->name('api.v1.monitors.history.index');

Route::put('/v1/installation/push-token', [InstallationPushTokenController::class, 'upsert'])
    ->middleware(['auth:sanctum', RequireInstallation::class, 'v1.json'])
    ->name('api.v1.installation.push-token.upsert');

Route::delete('/v1/installation/push-token', [InstallationPushTokenController::class, 'destroy'])
    ->middleware(['auth:sanctum', RequireInstallation::class])
    ->name('api.v1.installation.push-token.destroy');
