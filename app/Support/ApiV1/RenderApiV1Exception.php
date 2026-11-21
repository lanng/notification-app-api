<?php

namespace App\Support\ApiV1;

use App\Support\AccessAndPairing\AccessFailure;
use Illuminate\Auth\Access\AuthorizationException;
use Illuminate\Auth\AuthenticationException;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Validation\ValidationException;
use Symfony\Component\HttpKernel\Exception\HttpExceptionInterface;
use Symfony\Component\HttpKernel\Exception\TooManyRequestsHttpException;

class RenderApiV1Exception
{
    public static function render(\Throwable $exception, Request $request): ?JsonResponse
    {
        if (! $request->is('api/v1', 'api/v1/*')) {
            return null;
        }

        if ($exception instanceof AccessFailure) {
            $exception = new ApiProblem(
                $exception->status,
                $exception->errorCode,
                $exception->safeMessage,
                $exception->errors,
                $exception->headers,
            );
        }

        if ($exception instanceof ApiProblem) {
            return self::jsonResponse(
                $exception->status,
                $exception->errorCode,
                $exception->safeMessage,
                $exception->errors,
                $exception->headers,
            );
        }

        if ($exception instanceof AuthenticationException) {
            return self::jsonResponse(401, 'unauthenticated', 'Autenticação necessária.');
        }

        if ($exception instanceof AuthorizationException) {
            if ($exception->hasStatus() && $exception->status() === 404) {
                return self::notFoundResponse();
            }

            return self::accessDeniedResponse();
        }

        if ($exception instanceof ValidationException) {
            $errors = [];

            foreach ($exception->errors() as $field => $messages) {
                if (is_array($messages) && $messages !== []) {
                    $errors[$field] = ['O valor informado é inválido.'];
                }
            }

            return self::jsonResponse(
                422,
                'invalid_payload',
                'Os dados enviados são inválidos.',
                $errors,
            );
        }

        if ($exception instanceof TooManyRequestsHttpException) {
            $headers = [];
            $retryAfter = $exception->getHeaders()['Retry-After'] ?? null;

            if ((is_int($retryAfter) || is_string($retryAfter)) && ctype_digit((string) $retryAfter)) {
                $headers['Retry-After'] = (string) $retryAfter;
            }

            return self::jsonResponse(
                429,
                'rate_limited',
                'Limite de tentativas atingido.',
                headers: $headers,
            );
        }

        if ($exception instanceof HttpExceptionInterface) {
            return match ($exception->getStatusCode()) {
                400 => self::jsonResponse(400, 'bad_request', 'Requisição inválida.'),
                403 => self::accessDeniedResponse(),
                404 => self::notFoundResponse(),
                405 => self::methodNotAllowedResponse($exception),
                415 => self::jsonResponse(
                    415,
                    'unsupported_media_type',
                    'O tipo de conteúdo não é suportado.',
                ),
                default => self::internalErrorResponse(),
            };
        }

        return self::internalErrorResponse();
    }

    /**
     * @param  array<string, list<string>>  $errors
     * @param  array<string, string>  $headers
     */
    private static function jsonResponse(
        int $status,
        string $code,
        string $message,
        array $errors = [],
        array $headers = [],
    ): JsonResponse {
        $body = [
            'code' => $code,
            'message' => $message,
        ];

        if ($errors !== []) {
            $body['errors'] = $errors;
        }

        return response()->json($body, $status, $headers);
    }

    private static function accessDeniedResponse(): JsonResponse
    {
        return self::jsonResponse(403, 'access_denied', 'Ação não permitida.');
    }

    private static function notFoundResponse(): JsonResponse
    {
        return self::jsonResponse(404, 'not_found', 'Recurso não encontrado.');
    }

    private static function methodNotAllowedResponse(HttpExceptionInterface $exception): JsonResponse
    {
        $allowedMethods = $exception->getHeaders()['Allow'] ?? null;
        $safeMethods = is_string($allowedMethods)
            ? array_values(array_filter(
                array_map('trim', explode(',', $allowedMethods)),
                static fn (string $method): bool => in_array(
                    $method,
                    ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'TRACE', 'CONNECT'],
                    true,
                ),
            ))
            : [];

        return self::jsonResponse(
            405,
            'method_not_allowed',
            'Método não permitido.',
            headers: $safeMethods === [] ? [] : ['Allow' => implode(', ', $safeMethods)],
        );
    }

    private static function internalErrorResponse(): JsonResponse
    {
        return self::jsonResponse(500, 'internal_error', 'Erro interno do servidor.');
    }
}
