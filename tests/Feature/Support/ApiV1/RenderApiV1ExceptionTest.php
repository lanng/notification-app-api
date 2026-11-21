<?php

namespace Tests\Feature\Support\ApiV1;

use App\Support\ApiV1\ApiProblem;
use App\Support\ApiV1\RenderApiV1Exception;
use Illuminate\Auth\Access\AuthorizationException;
use Illuminate\Auth\AuthenticationException;
use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Database\Eloquent\ModelNotFoundException;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Validation\ValidationException;
use RuntimeException;
use Symfony\Component\HttpKernel\Exception\BadRequestHttpException;
use Symfony\Component\HttpKernel\Exception\HttpException;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;
use Symfony\Component\HttpKernel\Exception\TooManyRequestsHttpException;
use Symfony\Component\HttpKernel\Exception\UnsupportedMediaTypeHttpException;
use Tests\TestCase;

class RenderApiV1ExceptionTest extends TestCase
{
    public function test_unknown_api_v1_route_returns_a_contract_404_without_accept_header(): void
    {
        $response = $this->withoutHeader('Accept')->get('/api/v1/does-not-exist');

        $response->assertNotFound()->assertExactJson([
            'code' => 'not_found',
            'message' => 'Recurso não encontrado.',
        ]);
    }

    public function test_api_v1_root_is_inside_the_contract_404_scope(): void
    {
        $response = $this->withoutHeader('Accept')->get('/api/v1');

        $response->assertNotFound()->assertExactJson([
            'code' => 'not_found',
            'message' => 'Recurso não encontrado.',
        ]);
    }

    public function test_non_v1_paths_are_not_rendered_by_the_api_v1_renderer(): void
    {
        foreach (['/api/v10/resource', '/api/v1-other', '/api/health', '/up'] as $path) {
            $this->assertNull(RenderApiV1Exception::render(
                new RuntimeException('private exception'),
                Request::create($path, 'GET'),
            ));
        }
    }

    public function test_unknown_unversioned_api_route_keeps_its_message_only_404(): void
    {
        $response = $this->withoutHeader('Accept')->get('/api/does-not-exist');

        $response->assertNotFound()->assertExactJson([
            'message' => 'The route api/does-not-exist could not be found.',
        ]);
    }

    public function test_health_route_and_framework_health_endpoint_remain_successful(): void
    {
        $this->get('/api/health')->assertOk()->assertExactJson([
            'status' => 'ok',
        ]);

        $this->get('/up')->assertOk();
    }

    public function test_api_problem_fields_and_headers_are_rendered_directly(): void
    {
        $problem = new ApiProblem(
            422,
            'invalid_payload',
            'Os dados enviados são inválidos.',
            ['field' => ['O valor informado é inválido.']],
            ['X-Contract' => 'safe'],
        );

        $response = RenderApiV1Exception::render(
            $problem,
            Request::create('/api/v1/resource', 'POST'),
        );

        $this->assertInstanceOf(JsonResponse::class, $response);
        $this->assertSame(422, $response->getStatusCode());
        $this->assertSame([
            'code' => 'invalid_payload',
            'message' => 'Os dados enviados são inválidos.',
            'errors' => ['field' => ['O valor informado é inválido.']],
        ], $response->getData(true));
        $this->assertSame('safe', $response->headers->get('X-Contract'));
    }

    public function test_malformed_json_problem_keeps_its_existing_400_contract(): void
    {
        $response = RenderApiV1Exception::render(
            ApiProblem::malformedJson(),
            Request::create('/api/v1/resource', 'POST'),
        );

        $this->assertInstanceOf(JsonResponse::class, $response);
        $this->assertSame(400, $response->getStatusCode());
        $this->assertSame([
            'code' => 'malformed_json',
            'message' => 'O corpo JSON é inválido.',
        ], $response->getData(true));
    }

    public function test_authentication_exception_returns_safe_401(): void
    {
        $response = RenderApiV1Exception::render(
            new AuthenticationException('private credential'),
            Request::create('/api/v1/resource', 'GET'),
        );

        $this->assertInstanceOf(JsonResponse::class, $response);
        $this->assertSame(401, $response->getStatusCode());
        $this->assertSame([
            'code' => 'unauthenticated',
            'message' => 'Autenticação necessária.',
        ], $response->getData(true));
    }

    public function test_authorization_exception_returns_safe_403_after_laravel_prepares_it(): void
    {
        $response = $this->renderThroughHandler(
            new AuthorizationException('private authorization detail'),
        );

        $this->assertSame(403, $response->getStatusCode());
        $this->assertSame([
            'code' => 'access_denied',
            'message' => 'Ação não permitida.',
        ], $response->getData(true));
    }

    public function test_authorization_not_found_status_is_preserved_after_laravel_prepares_it(): void
    {
        $response = $this->renderThroughHandler(
            (new AuthorizationException('private authorization detail'))->asNotFound(),
        );

        $this->assertSame(404, $response->getStatusCode());
        $this->assertSame([
            'code' => 'not_found',
            'message' => 'Recurso não encontrado.',
        ], $response->getData(true));
    }

    public function test_general_http_403_returns_a_safe_access_denied_response(): void
    {
        $response = RenderApiV1Exception::render(
            new HttpException(403, 'private authorization detail'),
            Request::create('/api/v1/resource', 'GET'),
        );

        $this->assertInstanceOf(JsonResponse::class, $response);
        $this->assertSame(403, $response->getStatusCode());
        $this->assertSame([
            'code' => 'access_denied',
            'message' => 'Ação não permitida.',
        ], $response->getData(true));
    }

    public function test_not_found_exception_returns_safe_404(): void
    {
        $response = RenderApiV1Exception::render(
            new NotFoundHttpException('private route detail'),
            Request::create('/api/v1/resource', 'GET'),
        );

        $this->assertInstanceOf(JsonResponse::class, $response);
        $this->assertSame(404, $response->getStatusCode());
        $this->assertSame([
            'code' => 'not_found',
            'message' => 'Recurso não encontrado.',
        ], $response->getData(true));
    }

    public function test_model_not_found_returns_safe_404_after_laravel_prepares_it(): void
    {
        $exception = (new ModelNotFoundException)->setModel(
            'App\\Models\\PrivateRecord',
            'private-record-id',
        );

        $response = $this->renderThroughHandler($exception);

        $this->assertSame(404, $response->getStatusCode());
        $this->assertSame([
            'code' => 'not_found',
            'message' => 'Recurso não encontrado.',
        ], $response->getData(true));
    }

    public function test_bad_request_exception_returns_safe_400(): void
    {
        $response = RenderApiV1Exception::render(
            new BadRequestHttpException('private request detail'),
            Request::create('/api/v1/resource', 'POST'),
        );

        $this->assertInstanceOf(JsonResponse::class, $response);
        $this->assertSame(400, $response->getStatusCode());
        $this->assertSame([
            'code' => 'bad_request',
            'message' => 'Requisição inválida.',
        ], $response->getData(true));
    }

    public function test_unsupported_media_type_exception_returns_safe_415(): void
    {
        $response = RenderApiV1Exception::render(
            new UnsupportedMediaTypeHttpException('private content type'),
            Request::create('/api/v1/resource', 'POST'),
        );

        $this->assertInstanceOf(JsonResponse::class, $response);
        $this->assertSame(415, $response->getStatusCode());
        $this->assertSame([
            'code' => 'unsupported_media_type',
            'message' => 'O tipo de conteúdo não é suportado.',
        ], $response->getData(true));
    }

    public function test_validation_exception_preserves_field_keys_and_hides_rejected_values(): void
    {
        $response = RenderApiV1Exception::render(
            ValidationException::withMessages([
                'installationLabel' => ['Rejected SECRET token'],
                'ownerEmail' => ['private@example.test'],
            ]),
            Request::create('/api/v1/resource', 'POST'),
        );

        $this->assertInstanceOf(JsonResponse::class, $response);
        $this->assertSame(422, $response->getStatusCode());
        $this->assertSame([
            'code' => 'invalid_payload',
            'message' => 'Os dados enviados são inválidos.',
            'errors' => [
                'installationLabel' => ['O valor informado é inválido.'],
                'ownerEmail' => ['O valor informado é inválido.'],
            ],
        ], $response->getData(true));
    }

    public function test_validation_exception_omits_empty_field_errors(): void
    {
        $response = RenderApiV1Exception::render(
            ValidationException::withMessages([]),
            Request::create('/api/v1/resource', 'POST'),
        );

        $this->assertInstanceOf(JsonResponse::class, $response);
        $this->assertSame(422, $response->getStatusCode());
        $this->assertSame([
            'code' => 'invalid_payload',
            'message' => 'Os dados enviados são inválidos.',
        ], $response->getData(true));
    }

    public function test_rate_limit_response_preserves_only_a_safe_retry_after_header(): void
    {
        $response = RenderApiV1Exception::render(
            new TooManyRequestsHttpException(
                30,
                'private throttle detail',
                null,
                0,
                ['X-Secret' => 'internal value'],
            ),
            Request::create('/api/v1/resource', 'GET'),
        );

        $this->assertInstanceOf(JsonResponse::class, $response);
        $this->assertSame(429, $response->getStatusCode());
        $this->assertSame([
            'code' => 'rate_limited',
            'message' => 'Limite de tentativas atingido.',
        ], $response->getData(true));
        $this->assertSame('30', $response->headers->get('Retry-After'));
        $this->assertFalse($response->headers->has('X-Secret'));
    }

    public function test_unexpected_exception_returns_safe_500_even_when_debug_is_enabled(): void
    {
        config(['app.debug' => true]);

        $response = $this->renderThroughHandler(
            new RuntimeException('private token value'),
        );

        $this->assertSame(500, $response->getStatusCode());
        $this->assertSame([
            'code' => 'internal_error',
            'message' => 'Erro interno do servidor.',
        ], $response->getData(true));
    }

    private function renderThroughHandler(\Throwable $exception): JsonResponse
    {
        $response = app(ExceptionHandler::class)->render(
            Request::create('/api/v1/private', 'GET'),
            $exception,
        );

        $this->assertInstanceOf(JsonResponse::class, $response);

        return $response;
    }
}
