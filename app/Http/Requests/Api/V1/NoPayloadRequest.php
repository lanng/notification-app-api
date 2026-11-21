<?php

namespace App\Http\Requests\Api\V1;

use App\Support\ApiV1\ApiProblem;
use App\Support\ApiV1\JsonObject;
use Illuminate\Foundation\Http\FormRequest;

final class NoPayloadRequest extends FormRequest
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

    /** @return array{} */
    public function validatedPayload(): array
    {
        $jsonObject = $this->attributes->get('v1.json');

        if (! $jsonObject instanceof JsonObject) {
            throw ApiProblem::invalidPayload();
        }

        $jsonObject->only([]);

        return [];
    }
}
