<?php

namespace Dainis\AuthHandler\Interfaces;

use Dainis\AuthHandler\HttpClient\HttpClientInterface;
use Dainis\AuthHandler\Interfaces;

class RemoteKeyRetrievalStrategy implements KeyRetrievalStrategyInterface
{
    private HttpClientInterface $httpClient;
    private string $remoteServerUrl;

    public function __construct(HttpClientInterface $httpClient, string $remoteServerUrl)
    {
        $this->httpClient = $httpClient;
        $this->remoteServerUrl = $remoteServerUrl;
    }

    public function retrieveKey(string $kid): ?string
    {
        try {
            $response = $this->httpClient->get($this->remoteServerUrl . '/' . $kid);
            $data = json_decode($response, true, 512, JSON_THROW_ON_ERROR);

            return $data['key'] ?? null;
        } catch (\Throwable $e) {

            return null;
        }
    }
}
