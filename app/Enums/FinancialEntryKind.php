<?php

namespace App\Enums;

enum FinancialEntryKind: string
{
    case Reference = 'Reference';
    case TagDebit = 'TagDebit';
    case PixCredit = 'PixCredit';
}
