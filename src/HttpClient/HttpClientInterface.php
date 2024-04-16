<?php

namespace Dainis\AuthHandler\HttpClient;

interface HttpClientInterface
{
    public function get(string $url, array $headers = []): string;
}