<?php

namespace Dainis\AuthHandler;

use Firebase\JWT\JWT;
use Firebase\JWT\Key as JWTKey;
use GuzzleHttp\Client;
use GuzzleHttp\Exception\GuzzleException;

class AuthClient
{
    private $httpClient;
    private $config;

    public function __construct(array $config)
    {
        $this->config = $config;
        $this->httpClient = new Client(); // Assuming GuzzleHttp for HTTP requests
    }

    /**
     * Verifies the JWT token and, based on configuration, either fetches a dataset or an application code.
     *
     * @param string $jwtToken JWT token to verify.
     * @return mixed Depending on configuration, returns either a dataset or application code.
     * @throws \Exception on failure to verify the token, retrieve the key, or fetch data.
     */
    public function processRequest(string $jwtToken)
    {
        $decodedToken = $this->verifyToken($jwtToken);

        if ($this->config['return_type'] === 'dataset') {
            return $this->fetchDataSet($this->config['data_endpoint']);
        } elseif ($this->config['return_type'] === 'application_code') {
            return $this->fetchApplicationCode($this->config['app_code_repository']);
        } else {
            throw new \Exception("Invalid configuration for return type.");
        }
    }
    private function verifyToken(string $jwtToken): object
    {
        $payload = $this->getPayloadFromToken($jwtToken);
        $this->validateTokenExpiration($payload);
        $kid = $this->getKidFromToken($jwtToken);
        $key = $this->retrieveKey($kid);

        if (!$key) {
            throw new \Exception('Key could not be retrieved.');
        }

        return $this->verifyJwt($jwtToken, $key);
    }

    private function getPayloadFromToken(string $jwtToken): array
    {
        [$headerEncoded, $payloadEncoded] = explode('.', $jwtToken, 3);
        $payloadJson = base64_decode($payloadEncoded);
        return json_decode($payloadJson, true, 512, JSON_THROW_ON_ERROR);
    }

    private function getKidFromToken(string $jwtToken): string
    {
        [$headerEncoded] = explode('.', $jwtToken, 3);
        $headerJson = base64_decode($headerEncoded);
        $header = json_decode($headerJson, true, 512, JSON_THROW_ON_ERROR);
        return $header['kid'] ?? throw new \Exception('Token "kid" is missing.');
    }

    private function validateTokenExpiration(array $payload): void
    {
        if ($payload['exp'] < time()) {
            throw new \Exception('Token has expired.');
        }
    }

    private function verifyJwt(string $jwtToken, string $publicKey): object
    {
        try {
            return JWT::decode($jwtToken, new JWTKey($publicKey, 'RS256'));
        } catch (\Exception $e) {
            throw new \Exception('Token is invalid.', 0, $e);
        }
    }

    private function retrieveKey(string $kid): ?string
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
                if (!empty($this->config['bearer_token'])) {
                    $options['headers'] = ['Authorization' => 'Bearer ' . $this->config['bearer_token']];
                }
                $response = $this->httpClient->get($url, $options);

                // Check response status
                if ($response->getStatusCode() != 200) {
                    throw new \Exception("HTTP error " . $response->getStatusCode() . " received from " . $url);
                }

                $data = json_decode($response->getBody()->getContents(), true, 512, JSON_THROW_ON_ERROR);
                return $data['key'] ?? null;
            } catch (GuzzleException $e) {
                throw new \Exception("Failed to retrieve key from remote server. URL: " . $url . " Error: " . $e->getMessage(), 0, $e);
            }
        }

        return null;
    }

    /**
     * Fetches a dataset from a specified endpoint.
     *
     * @param string $endpoint URL to fetch the dataset from.
     * @return mixed Dataset obtained from the endpoint.
     */
    private function fetchDataSet(string $endpoint)
    {
        try {
            $response = $this->httpClient->get($endpoint);
            return json_decode($response->getBody()->getContents(), true);
        } catch (GuzzleException $e) {
            throw new \Exception("Failed to fetch dataset.", 0, $e);
        }
    }

    /**
     * Fetches application code from a repository.
     *
     * @param string $repositoryUrl URL to the repository containing the application code.
     * @return string Application code as a string or packaged format.
     */
    private function fetchApplicationCode(string $repositoryUrl)
    {
        try {
            $response = $this->httpClient->get($repositoryUrl);
            return $response->getBody()->getContents();
        } catch (GuzzleException $e) {
            throw new \Exception("Failed to fetch application code.", 0, $e);
        }
    }
}