<?php

namespace Dainis\AuthHandler\Utils;

class TokenHelper
{
    public static function parseToken(string $jwtToken): array
    {
        [$header, $payload, $signature] = explode('.', $jwtToken);
        return [
            'header' => json_decode(base64_decode($header), true),
            'payload' => json_decode(base64_decode($payload), true),
            'signature' => $signature
        ];
    }
}