<?php

namespace App\Providers;

use App\Support\AccessAndPairing\DisabledOwnerIdentityVerifier;
use App\Support\AccessAndPairing\OwnerIdentityVerifier;
use Illuminate\Support\ServiceProvider;

class AppServiceProvider extends ServiceProvider
{
    /**
     * Register any application services.
     */
    public function register(): void
    {
        $this->app->bind(OwnerIdentityVerifier::class, DisabledOwnerIdentityVerifier::class);
    }

    /**
     * Bootstrap any application services.
     */
    public function boot(): void
    {
        //
    }
}
