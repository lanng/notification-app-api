<?php

namespace App\Support\ApiV1;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class RequireJsonObject
{
    /**
     * @param  Closure(Request): Response  $next
     */
    public function handle(Request $request, Closure $next): Response
    {
        if (! $request->is('api/v1', 'api/v1/*') || ! in_array($request->method(), ['POST', 'PUT', 'PATCH', 'DELETE'], true)) {
            return $next($request);
        }

        $body = $request->getContent();

        if ($body === '') {
            $jsonObject = JsonObject::decode('{}');
        } else {
            $contentType = $request->headers->get('Content-Type');
            $mediaType = $contentType === null
                ? null
                : strtolower(trim(explode(';', $contentType, 2)[0]));

            if ($mediaType !== 'application/json') {
                throw ApiProblem::unsupportedMediaType();
            }

            $jsonObject = JsonObject::decode($body);
        }

        $request->attributes->set('v1.json', $jsonObject);

        return $next($request);
    }
}
