<?php

namespace App\Http\Requests\Api\V1;

use App\Support\ApiV1\ApiProblem;
use App\Support\ApiV1\JsonObject;
use App\Support\ApiV1\JsonTypes;
use Illuminate\Foundation\Http\FormRequest;

final class RedeemInvitationRequest extends FormRequest
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
     * @return array{invitationSecret: string, installationLabel: ?string}
     */
    public function validatedPayload(): array
    {
        $jsonObject = $this->attributes->get('v1.json');

        if (! $jsonObject instanceof JsonObject) {
            throw ApiProblem::invalidPayload();
        }

        $payload = $jsonObject->only(
            ['invitationSecret', 'installationLabel'],
            ['invitationSecret'],
        );
        $invitationSecret = JsonTypes::requireString(
            $payload['invitationSecret'],
            'invitationSecret',
            max: 43,
        );

        if (
            preg_match('/\A[A-Za-z0-9_-]{43}\z/', $invitationSecret) !== 1
            || strlen((string) base64_decode(
                strtr($invitationSecret, '-_', '+/').'=',
                strict: true,
            )) !== 32
        ) {
            throw ApiProblem::invalidPayload('invitationSecret');
        }

        $installationLabel = array_key_exists('installationLabel', $payload)
            ? JsonTypes::requireString($payload['installationLabel'], 'installationLabel', max: 128)
            : null;

        return [
            'invitationSecret' => $invitationSecret,
            'installationLabel' => $installationLabel,
        ];
    }
}
