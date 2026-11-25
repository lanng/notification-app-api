<?php

namespace App\Http\Requests\Api\V1;

use App\Support\ApiV1\ApiProblem;
use App\Support\ApiV1\JsonObject;
use App\Support\ApiV1\JsonTypes;
use Illuminate\Foundation\Http\FormRequest;

final class UpsertPushTokenRequest extends FormRequest
{
    public function authorize(): bool
    {
        return true;
    }

    /** @return array<string, never> */
    public function rules(): array
    {
        return [];
    }

    /**
     * @return array{fcmToken: string}
     */
    public function validatedPayload(): array
    {
        $jsonObject = $this->attributes->get('v1.json');

        if (! $jsonObject instanceof JsonObject) {
            throw ApiProblem::invalidPayload();
        }

        $payload = $jsonObject->only(['fcmToken'], ['fcmToken']);
        $fcmToken = trim(JsonTypes::requireString($payload['fcmToken'], 'fcmToken', max: 512));

        if ($fcmToken === '' || preg_match('/\s/', $fcmToken) === 1) {
            throw ApiProblem::invalidPayload('fcmToken');
        }

        return ['fcmToken' => $fcmToken];
    }
}
