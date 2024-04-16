<?php

namespace Dainis\AuthHandler;

use Firebase\JWT\ExpiredException;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Firebase\JWT\SignatureInvalidException;

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
            try {
                $decoded = JWT::decode($jwt, new Key($this->publicKey, 'RS256'));

                if ($decoded->exp < time()) {
                    throw new \Exception("Token has expired.");
                }
                return $decoded;
            } catch (ExpiredException $e) {
                throw new \Exception("Token has expired.");
            } catch (SignatureInvalidException $e) {
                throw new \Exception("Invalid signature.");
            } catch (\Exception $e) {
                throw new \Exception("JWT validation error: " . $e->getMessage());
            }
        } catch (\Exception $e) {
            throw new \Exception("Invalid token: " . $e->getMessage());
        }
    }
}
