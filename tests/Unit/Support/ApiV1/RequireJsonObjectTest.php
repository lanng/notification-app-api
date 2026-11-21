<?php

namespace Tests\Unit\Support\ApiV1;

use App\Support\ApiV1\ApiProblem;
use App\Support\ApiV1\JsonObject;
use App\Support\ApiV1\RequireJsonObject;
use Illuminate\Http\Request as NativeRequest;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Response;

class RequireJsonObjectTest extends TestCase
{
    public static function writeMethods(): array
    {
        return [
            'post' => ['POST'],
            'put' => ['PUT'],
            'patch' => ['PATCH'],
            'delete' => ['DELETE'],
        ];
    }

    public static function nonWriteMethods(): array
    {
        return [
            'get' => ['GET'],
            'head' => ['HEAD'],
            'options' => ['OPTIONS'],
            'trace' => ['TRACE'],
            'query' => ['QUERY'],
            'custom method' => ['BREW'],
        ];
    }

    public static function pathsOutsideV1(): array
    {
        return [
            'next version prefix' => ['/api/v10'],
            'similar version path' => ['/api/v1-other'],
            'health endpoint' => ['/api/health'],
            'outside api' => ['/outside'],
        ];
    }

    public static function unsupportedMediaTypes(): array
    {
        return [
            'missing content type' => [null],
            'empty content type' => [''],
            'plain text' => ['text/plain'],
            'json structured suffix' => ['application/problem+json'],
        ];
    }

    public static function nonObjectJsonRoots(): array
    {
        return [
            'array' => ['[]'],
            'null' => ['null'],
            'number' => ['7'],
            'boolean' => ['true'],
            'string' => ['"text"'],
        ];
    }

    #[DataProvider('writeMethods')]
    public function test_write_requests_attach_json_object_without_coercing_or_merging_input(string $method): void
    {
        $body = '{"enabled":false,"count":"0"}';
        $request = $this->newRequest('/api/v1/resource', $method, $body, 'application/json; charset=utf-8');
        $nextRequest = null;

        $response = (new RequireJsonObject)->handle(
            $request,
            function (NativeRequest $passedRequest) use (&$nextRequest): Response {
                $nextRequest = $passedRequest;

                return new Response(status: 204);
            },
        );

        $jsonObject = $request->attributes->get('v1.json');

        $this->assertSame($request, $nextRequest);
        $this->assertInstanceOf(JsonObject::class, $jsonObject);
        $this->assertSame(['enabled' => false, 'count' => '0'], $jsonObject->only(['enabled', 'count']));
        $this->assertSame(['v1.json' => $jsonObject], $request->attributes->all());
        $this->assertSame([], $request->request->all());
        $this->assertSame($body, $request->getContent());
        $this->assertSame(204, $response->getStatusCode());
    }

    public function test_exactly_empty_write_body_attaches_empty_object_without_requiring_json_content_type(): void
    {
        foreach ([null, 'text/plain'] as $contentType) {
            $request = $this->newRequest('/api/v1', 'POST', '', $contentType);

            $response = $this->sendThroughMiddleware($request);
            $jsonObject = $request->attributes->get('v1.json');

            $this->assertInstanceOf(JsonObject::class, $jsonObject);
            $this->assertSame([], $jsonObject->only([]));
            $this->assertSame(204, $response->getStatusCode());

            try {
                $jsonObject->only(['requiredField'], ['requiredField']);
                self::fail('The empty object must fail caller-required field validation.');
            } catch (ApiProblem $problem) {
                $this->assertSame(422, $problem->status);
                $this->assertSame('invalid_payload', $problem->errorCode);
                $this->assertSame('Os dados enviados são inválidos.', $problem->safeMessage);
                $this->assertSame([], $problem->errors);
            }
        }
    }

    public function test_json_content_type_is_case_insensitive_and_allows_parameters(): void
    {
        $request = $this->newRequest(
            '/api/v1/resource',
            'POST',
            '{"enabled":true}',
            ' Application/JSON ; charset=UTF-8',
        );

        $response = $this->sendThroughMiddleware($request);

        $this->assertInstanceOf(JsonObject::class, $request->attributes->get('v1.json'));
        $this->assertSame(204, $response->getStatusCode());
    }

    #[DataProvider('unsupportedMediaTypes')]
    public function test_nonempty_write_body_without_exact_json_media_type_returns_415(?string $contentType): void
    {
        $request = $this->newRequest('/api/v1/resource', 'POST', '{"enabled":true}', $contentType);

        $this->assertApiProblem(
            fn () => $this->sendThroughMiddleware($request),
            415,
            'unsupported_media_type',
        );
        $this->assertFalse($request->attributes->has('v1.json'));
    }

    public function test_malformed_nonempty_json_body_returns_400(): void
    {
        $request = $this->newRequest('/api/v1/resource', 'POST', '{"enabled":', 'application/json');

        $this->assertApiProblem(
            fn () => $this->sendThroughMiddleware($request),
            400,
            'malformed_json',
        );
        $this->assertFalse($request->attributes->has('v1.json'));
    }

    public function test_whitespace_only_write_body_is_not_treated_as_empty_and_returns_400(): void
    {
        $request = $this->newRequest('/api/v1/resource', 'POST', " \n\t", 'application/json');

        $this->assertApiProblem(
            fn () => $this->sendThroughMiddleware($request),
            400,
            'malformed_json',
        );
        $this->assertFalse($request->attributes->has('v1.json'));
    }

    #[DataProvider('nonObjectJsonRoots')]
    public function test_non_object_json_root_returns_422(string $body): void
    {
        $request = $this->newRequest('/api/v1/resource', 'POST', $body, 'application/json');

        $this->assertApiProblem(
            fn () => $this->sendThroughMiddleware($request),
            422,
            'invalid_payload',
        );
        $this->assertFalse($request->attributes->has('v1.json'));
    }

    public function test_unknown_fields_remain_in_json_object_for_caller_allowlist_validation(): void
    {
        $request = $this->newRequest(
            '/api/v1/resource',
            'POST',
            '{"enabled":false,"futureField":"preserved"}',
            'application/json',
        );

        $this->sendThroughMiddleware($request);
        $jsonObject = $request->attributes->get('v1.json');

        $this->assertInstanceOf(JsonObject::class, $jsonObject);
        $this->assertSame(['enabled' => false, 'futureField' => 'preserved'], $jsonObject->only(['enabled', 'futureField']));
        $this->assertApiProblem(
            fn () => $jsonObject->only(['enabled']),
            422,
            'invalid_payload',
        );
        $this->assertSame([], $request->request->all());
    }

    #[DataProvider('nonWriteMethods')]
    public function test_non_write_method_bypasses_payload_validation(string $method): void
    {
        $request = $this->newRequest('/api/v1/resource', $method, 'not json', 'text/plain');

        $response = $this->sendThroughMiddleware($request);

        $this->assertSame(204, $response->getStatusCode());
        $this->assertFalse($request->attributes->has('v1.json'));
    }

    #[DataProvider('pathsOutsideV1')]
    public function test_path_outside_v1_bypasses_payload_validation(string $path): void
    {
        $request = $this->newRequest($path, 'POST', 'not json', 'text/plain');

        $response = $this->sendThroughMiddleware($request);

        $this->assertSame(204, $response->getStatusCode());
        $this->assertFalse($request->attributes->has('v1.json'));
    }

    private function sendThroughMiddleware(NativeRequest $request): Response
    {
        return (new RequireJsonObject)->handle(
            $request,
            static fn (NativeRequest $passedRequest): Response => new Response(status: 204),
        );
    }

    private function newRequest(
        string $path,
        string $method,
        string $body,
        ?string $contentType,
    ): NativeRequest {
        $server = [
            'REQUEST_METHOD' => $method,
            'REQUEST_URI' => $path,
        ];

        if ($contentType !== null) {
            $server['CONTENT_TYPE'] = $contentType;
        }

        return new NativeRequest(server: $server, content: $body);
    }

    private function assertApiProblem(callable $operation, int $status, string $errorCode): void
    {
        try {
            $operation();
            self::fail('The request must be rejected with an API problem.');
        } catch (ApiProblem $problem) {
            $this->assertSame($status, $problem->status);
            $this->assertSame($errorCode, $problem->errorCode);
        }
    }
}
