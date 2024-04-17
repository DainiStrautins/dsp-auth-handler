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
    private function verifyToken(string $jwtToken): object
    {
        $payload = $this->getPayloadFromToken($jwtToken);
        $this->validateTokenExpiration($payload);
        $kid = $this->getKidFromToken($jwtToken);
        $key = $this->retrieveKey($kid, $jwtToken);

        if (!$key) {
            throw new Exception('Key could not be retrieved.');
        }

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
        // First, attempt to retrieve the key locally
        $filePath = $this->config['keys_directory'] . DIRECTORY_SEPARATOR . $kid;
        if (is_readable($filePath)) {
            return file_get_contents($filePath);
        }

        // If not found locally, retrieve from remote server
        if ($this->config['use_remote_key_retrieval']) {
            try {
                $url = rtrim($this->config['remote_server_url'], '/') . '/' . urlencode($kid);

                $options = [];
                $options['headers'] = ['Authorization' => 'Bearer ' . $jwtToken];
                $response = $this->httpClient->get($url, $options);

                // Check response status
                if ($response->getStatusCode() != 200) {
                    throw new Exception("HTTP error " . $response->getStatusCode() . " received from " . $url);
                }

                $data = json_decode($response->getBody()->getContents(), true, 512, JSON_THROW_ON_ERROR);
                return $data['key'] ?? null;
            } catch (GuzzleException $e) {
                throw new Exception("Failed to retrieve key from remote server. URL: " . $url . " Error: " . $e->getMessage(), 0, $e);
            }
        }

        return null;
    }
}