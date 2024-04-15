<?php

namespace Dainis\AuthHandler;

use Firebase\JWT\JWT;
use Firebase\JWT\Key;

class JWTService
{
    private $publicKey;

    public function __construct($publicKey)
    {
        $this->publicKey = $publicKey;
    }

    public function validateToken($jwt)
    {
        try {
            // Decoding the JWT with the provided public key
            $decoded = JWT::decode($jwt, new Key($this->publicKey, 'RS256'));

            // Check if the token is expired
            if ($decoded->exp < time()) {
                throw new \Exception("Token has expired.");
            }

            return $decoded;
        } catch (\Exception $e) {
            throw new \Exception("Invalid token: " . $e->getMessage());
        }
    }
}
