<?php

namespace App\Enums;

enum PairingRequestStatus: string
{
    case Pending = 'Pending';
    case Approved = 'Approved';
    case Rejected = 'Rejected';
    case Expired = 'Expired';
    case Cancelled = 'Cancelled';
}
