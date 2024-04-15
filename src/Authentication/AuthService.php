<?php

namespace Dainis\AuthHandler\Authentication;

use Dainis\AuthHandler\Config\Config;

use GuzzleHttp\Client;

class AuthService {
    private $config;

    public function __construct(Config $config) {
        $this->config = $config;
    }

    public function authenticate($username, $password) {
        $client = new Client();
        $response = $client->post($this->config->get('apiEndpoint'), [
            'form_params' => [
                'username' => $username,
                'password' => $password
            ]
        ]);

        $data = json_decode($response->getBody(), true);
        return $data['accessToken'] ?? null;  // Assume the token is returned as 'accessToken'
    }
}
