<?php

namespace Dainis\AuthHandler\Token;

use Firebase\JWT\JWT;
use Firebase\JWT\Key;

class TokenService {
    private $publicKey;
    private $publicKeyExpire;

    public function __construct($publicKey, $expireAt) {
        $this->publicKey = $publicKey;
        $this->publicKeyExpire = $expireAt;
    }

    /**
     * @throws \Exception
     */
    public function validateToken($jwt): \stdClass
    {
        if ($this->isPublicKeyExpired()) {
            throw new \Exception("Public key expired.");
        }

        $algorithms = ['RS256'];  // Define the array as a variable
        return JWT::decode($jwt, new Key($this->publicKey, 'RS256'));
    }

    private function isPublicKeyExpired(): bool
    {
        return $this->publicKeyExpire < time();
    }
}