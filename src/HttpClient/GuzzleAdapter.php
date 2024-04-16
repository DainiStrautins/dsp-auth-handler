<?php

namespace Dainis\AuthHandler\HttpClient;

use GuzzleHttp\Client;

class GuzzleAdapter implements HttpClientInterface
{
    private Client $client;

    public function __construct(Client $client)
    {
        $this->client = $client;
    }

    public function get(string $url, array $headers = []): string
    {
        $response = $this->client->get($url, [
            'headers' => $headers
        ]);
        return $response->getBody()->getContents();
    }
}