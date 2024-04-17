<?php

namespace Dainis\AuthHandler\Interfaces;

use Dainis\AuthHandler\HttpClient\HttpClientInterface;
use Dainis\AuthHandler\Interfaces;

class RemoteKeyRetrievalStrategy implements KeyRetrievalStrategyInterface
{
    private HttpClientInterface $httpClient;
    private string $remoteServerUrl;
    private string $bearerToken;

    public function __construct(HttpClientInterface $httpClient, string $remoteServerUrl, string $bearerToken)
    {
        $this->httpClient = $httpClient;
        $this->remoteServerUrl = $remoteServerUrl;
        $this->bearerToken = $bearerToken;
    }

    public function retrieveKey(string $kid): ?string
    {
        try {
            $headers = [];
            if ($this->bearerToken) {
                $headers['Authorization'] = 'Bearer ' . $this->bearerToken;
            }

            $response = $this->httpClient->get($this->remoteServerUrl . '/' . $kid, $headers);
            $data = json_decode($response, true, 512, JSON_THROW_ON_ERROR);

            return $data['key'] ?? null;
        } catch (\Throwable $e) {

            return null;
        }
    }
}
