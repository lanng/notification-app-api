<?php

namespace Tests\Feature;

use Composer\InstalledVersions;
use Kreait\Firebase\Contract\Auth;
use Kreait\Firebase\JWT\Action\FetchGooglePublicKeys\WithGuzzle;
use Kreait\Firebase\JWT\Action\VerifyIdToken\WithLcobucciJWT;
use Kreait\Firebase\JWT\GooglePublicKeys;
use Kreait\Firebase\JWT\IdTokenVerifier;
use Tests\TestCase;

class FirebaseIdentityDependencyTest extends TestCase
{
    public function test_firebase_auth_contract_is_installed(): void
    {
        $this->assertTrue(interface_exists(Auth::class));
    }

    public function test_firebase_packages_use_the_approved_versions(): void
    {
        $this->assertSame('8.7.0', InstalledVersions::getPrettyVersion('kreait/firebase-php'));
        $this->assertSame('5.6.2', InstalledVersions::getPrettyVersion('kreait/firebase-tokens'));
    }

    public function test_firebase_token_verifier_composition_types_are_autoloadable(): void
    {
        $this->assertTrue(class_exists(IdTokenVerifier::class));
        $this->assertTrue(class_exists(GooglePublicKeys::class));
        $this->assertTrue(class_exists(WithGuzzle::class));
        $this->assertTrue(class_exists(WithLcobucciJWT::class));
    }
}
