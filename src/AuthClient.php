<?php

namespace Dainis\AuthHandler;

use Exception;
use Firebase\JWT\JWT;
use Firebase\JWT\Key as JWTKey;
use GuzzleHttp\Client;
use GuzzleHttp\Exception\GuzzleException;
use JsonException;

class AuthClient
{
    private Client $httpClient;
    private array $config;

    public function __construct(array $config)
    {
        $this->config = $config;
        $this->httpClient = new Client(); // Assuming GuzzleHttp for HTTP requests
    }

    /**
     * @throws JsonException
     * @throws Exception
     */
    public function verifyToken(string $jwtToken): object
    {
        $payload = $this->getPayloadFromToken($jwtToken);
        $this->validateTokenExpiration($payload);
        $kid = $this->getKidFromToken($jwtToken);
        $key = $this->retrieveKey($kid, $jwtToken);

        if (!$key) {
            throw new Exception('Key could not be retrieved.');
        }

        $this->verifyKeyConsistency($key, $kid);

        // Proceed to verify the JWT with the key
        return $this->verifyJwt($jwtToken, $key);
    }

    /**
     * @throws JsonException
     */
    private function getPayloadFromToken(string $jwtToken): array
    {
        [$headerEncoded, $payloadEncoded] = explode('.', $jwtToken, 3);
        $payloadJson = base64_decode($payloadEncoded);
        return json_decode($payloadJson, true, 512, JSON_THROW_ON_ERROR);
    }

    /**
     * @throws JsonException
     * @throws Exception
     */
    private function getKidFromToken(string $jwtToken): string
    {
        [$headerEncoded] = explode('.', $jwtToken, 3);
        $headerJson = base64_decode($headerEncoded);
        $header = json_decode($headerJson, true, 512, JSON_THROW_ON_ERROR);
        return $header['kid'] ?? throw new Exception('Token "kid" is missing.');
    }

    /**
     * @throws Exception
     */
    private function validateTokenExpiration(array $payload): void
    {
        if ($payload['exp'] < time()) {
            throw new Exception('Token has expired.');
        }
    }

    /**
     * Verifies the consistency of the public key with the Key ID (kid) from the JWT header.
     *
     * @param string $publicKey The decrypted public key.
     * @param string $kid The Key ID (kid) from the JWT header.
     * @throws Exception If the computed 'kid' does not match the provided 'kid'.
     */
    public function verifyKeyConsistency(string $publicKey, string $kid): void
    {
        // Compute the Key ID (kid) from the decrypted public key
        $computedKid = hash('sha256', $publicKey);

        // Verify that the computed 'kid' matches the 'kid' from the JWT header
        if ($computedKid !== $kid) {
            throw new Exception('Public key mismatch.');
        }
    }

    /**
     * @throws Exception
     */
    private function verifyJwt(string $jwtToken, string $publicKey): object
    {
        try {
            return JWT::decode($jwtToken, new JWTKey($publicKey, 'RS256'));
        } catch (Exception $e) {
            throw new Exception('Token is invalid.', 0, $e);
        }
    }

    /**
     * @throws JsonException
     * @throws Exception
     */
    private function retrieveKey(string $kid, string $jwtToken): ?string
    {
        $filePath = $this->config['keys_directory'] . DIRECTORY_SEPARATOR . $kid;

        if (is_readable($filePath)) {
            return file_get_contents($filePath);
        }

        if ($this->config['use_remote_key_retrieval']) {
            try {
                $url = rtrim($this->config['remote_server_url'], '/') . '/' . urlencode($kid);
                $options = [
                    'headers' => ['Authorization' => 'Bearer ' . $jwtToken]
                ];
                $response = $this->httpClient->get($url, $options);

                // Check response status
                if ($response->getStatusCode() != 200) {
                    throw new Exception("HTTP error " . $response->getStatusCode() . " received from " . $url);
                }

                $data = json_decode($response->getBody()->getContents(), true, 512, JSON_THROW_ON_ERROR);
                $key = $data['key'] ?? null;

                if ($key !== null) {
                    // Store the key locally if retrieved from remote server
                    file_put_contents($filePath, $key);
                }

                return $key;
            } catch (GuzzleException $e) {
                throw new Exception("Failed to retrieve key from remote server. URL: " . $url . " Error: " . $e->getMessage(), 0, $e);
            }
        }

        return null;
    }
}