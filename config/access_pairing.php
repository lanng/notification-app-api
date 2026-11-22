<?php

return [
    'owner' => [
        'firebase_project_id' => env('ACCESS_PAIRING_OWNER_FIREBASE_PROJECT_ID'),
        'firebase_uid' => env('ACCESS_PAIRING_OWNER_FIREBASE_UID'),
    ],
    'firebase' => [
        'enabled' => env('ACCESS_PAIRING_FIREBASE_ENABLED', false),
        'credentials_path' => env('ACCESS_PAIRING_FIREBASE_CREDENTIALS'),
        'connect_timeout' => 3.0,
        'timeout' => 5.0,
    ],
];
