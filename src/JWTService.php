<?php

namespace Dainis\AuthHandler;

use Firebase\JWT\JWT;
use Firebase\JWT\Key;

class JWTService
{
    private $secretKey;

    public function __construct($secretKey)
    {
        $this->secretKey = $secretKey;
    }

    public function validateToken($jwt)
    {
        try {
            // Decoding the JWT with the provided secret key
            $decoded = JWT::decode($jwt, new Key($this->secretKey, 'HS256'));
            return $decoded;
        } catch (\Firebase\JWT\ExpiredException $e) {
            throw new \Exception("Token has expired: " . $e->getMessage());
        } catch (\Firebase\JWT\SignatureInvalidException $e) {
            throw new \Exception("Invalid signature: " . $e->getMessage());
        } catch (\Firebase\JWT\BeforeValidException $e) {
            throw new \Exception("Token is not yet valid: " . $e->getMessage());
        } catch (\UnexpectedValueException $e) {
            throw new \Exception("JWT validation error: " . $e->getMessage());
        } catch (\Exception $e) {
            throw new \Exception("Error decoding token: " . $e->getMessage());
        }
    }
}