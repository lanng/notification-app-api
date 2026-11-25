<?php

namespace App\Http\Controllers\Api\V1;

use App\Http\Controllers\Controller;
use App\Support\AccessAndPairing\AccessContext;
use App\Support\AccessAndPairing\AccessFailure;
use App\Support\ApiV1\ApiProblem;
use App\Support\SharedMonitor\SharedMonitorSync;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

final class MonitorHistoryController extends Controller
{
    private const array ALLOWED_FILTERS = ['all', 'entries', 'exits', 'adjustments'];

    public function index(
        Request $request,
        string $monitor,
        SharedMonitorSync $sharedMonitorSync,
    ): JsonResponse {
        $context = $this->accessContext($request);

        $beforeRaw = $request->query('beforeEntryId');
        $beforeEntryId = null;

        if ($beforeRaw !== null && $beforeRaw !== '') {
            if (! is_string($beforeRaw) || preg_match('/\A[1-9][0-9]*\z/', $beforeRaw) !== 1) {
                throw ApiProblem::invalidPayload('beforeEntryId');
            }

            $beforeEntryId = (int) $beforeRaw;
        }

        $limitRaw = $request->query('limit');
        $limit = 30;

        if ($limitRaw !== null && $limitRaw !== '') {
            if (! is_string($limitRaw) || preg_match('/\A[1-9][0-9]*\z/', $limitRaw) !== 1) {
                throw ApiProblem::invalidPayload('limit');
            }

            $limit = (int) $limitRaw;

            if ($limit > 100) {
                throw ApiProblem::invalidPayload('limit');
            }
        }

        $filterRaw = $request->query('filter', 'all');
        $filter = is_string($filterRaw) && $filterRaw !== '' ? strtolower($filterRaw) : 'all';

        if (! in_array($filter, self::ALLOWED_FILTERS, true)) {
            throw ApiProblem::invalidPayload('filter');
        }

        return response()->json([
            'data' => $sharedMonitorSync->listMonitorHistory(
                context: $context,
                requestedMonitorId: $monitor,
                beforeEntryId: $beforeEntryId,
                limit: $limit,
                filter: $filter,
            ),
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
