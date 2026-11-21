<?php

namespace App\Http\Requests\Api\V1;

use App\Support\ApiV1\ApiProblem;
use App\Support\ApiV1\JsonObject;
use App\Support\ApiV1\JsonTypes;
use Illuminate\Foundation\Http\FormRequest;

final class ActivateHostRequest extends FormRequest
{
    public function authorize(): bool
    {
        return true;
    }

    /**
     * @return array<string, never>
     */
    public function rules(): array
    {
        return [];
    }

    /**
     * @return array{confirmation: true, expectedGeneration: string}
     */
    public function validatedPayload(): array
    {
        $jsonObject = $this->attributes->get('v1.json');

        if (! $jsonObject instanceof JsonObject) {
            throw ApiProblem::invalidPayload();
        }

        $payload = $jsonObject->only(
            ['confirmation', 'expectedGeneration'],
            ['confirmation', 'expectedGeneration'],
        );
        $confirmation = JsonTypes::requireBoolean($payload['confirmation'], 'confirmation');

        if (! $confirmation) {
            throw ApiProblem::invalidPayload('confirmation');
        }

        return [
            'confirmation' => true,
            'expectedGeneration' => JsonTypes::requireDecimalString(
                $payload['expectedGeneration'],
                'expectedGeneration',
                canonical: true,
            ),
        ];
    }
}
