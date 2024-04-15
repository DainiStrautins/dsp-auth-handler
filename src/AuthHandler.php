<?php

namespace Dainis\AuthHandler;

use GuzzleHttp\Client;

class AuthHandler
{
    private $authServiceEndpoint;
    private $httpClient;

    public function __construct($authServiceEndpoint)
    {
        $this->authServiceEndpoint = $authServiceEndpoint;
        $this->httpClient = new Client();
    }

    public function fetchApplicationData($accessToken)
    {
        try {
            $response = $this->httpClient->request('GET', $this->authServiceEndpoint, [
                'headers' => [
                    'Authorization' => 'Bearer ' . $accessToken
                ]
            ]);

            $data = json_decode($response->getBody()->getContents(), true);
            return $data;
        } catch (\Exception $e) {
            throw new \Exception("Failed to fetch application data: " . $e->getMessage());
        }
    }
}
