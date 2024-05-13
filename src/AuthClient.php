<?php

namespace Dainis\AuthHandler;

use Exception;
use Firebase\JWT\JWT;
use Firebase\JWT\Key as JWTKey;
use GuzzleHttp\Client;
use GuzzleHttp\Exception\RequestException;
use GuzzleHttp\Exception\GuzzleException;

class AuthClient
{
    private Client $httpClient;
    private array $config;
    private string $keysDirectory;
    private string $remoteServerUrl;
    private bool $useRemoteKeyRetrieval;
    private ?string $jwtToken = null;
    private array $jwtPartsEncoded = [];
    private array $jwtParts = [];
    private bool $isJwtValid = false;
    private ?string $key = null;
    private ?string $kid = null;

    private ?array $protectedResources = [];

    /**
     * @throws GuzzleException
     */
    public function __construct(array $config, ?string $jwtToken = null)
    {
        $this->config = $config;
        $this->httpClient = new Client();
        $this->keysDirectory = rtrim($config['keys_directory'], DIRECTORY_SEPARATOR);
        $this->remoteServerUrl = rtrim($config['remote_server_url'], '/');
        $this->useRemoteKeyRetrieval = $config['use_remote_key_retrieval'] ?? false;
        $this->protectedResources = $config['protected_resources'] ?? [];
        $autoAuthenticate = $config['auto_authenticate'] ?? false;

        if ($autoAuthenticate) {
            $this->isJwtValid = true;
        } else {
            try {
                $this->processJwt($jwtToken);
                $this->isJwtValid = true;
            } catch (Exception $e) {
                $this->isJwtValid = false;
                $this->lastError = $e->getMessage();
            }
        }
    }


    public function isJwtValid(): bool
    {
        return $this->isJwtValid;
    }

    /**
     * Processes the JWT by extracting it from the Authorization header, parsing its components, validating claims,
     * retrieving the cryptographic key, and verifying the JWT.
     * @throws Exception If the JWT token is not found, is malformed, if validation checks fail, if the key cannot be retrieved,
     * @throws GuzzleException
     * if the key consistency check fails, or if JWT verification fails.
     */
    private function processJwt(?string $jwtToken = null): void
    {
        $requestedResource = $_SERVER['REQUEST_URI'];
        $isProtected = !in_array($requestedResource, $this->config['protected_resources']['unprotected'] ?? []);

        if (!$isProtected) {
            return;
        }

        if ($jwtToken === null) {
            $headers = getallheaders();
            if (!empty($headers['Authorization']) && preg_match('/Bearer\s(\S+)/', $headers['Authorization'], $matches)) {
                $this->jwtToken = $matches[1];
            }  elseif (!empty($_COOKIE['jwt'])) {
                $this->jwtToken = $_COOKIE['jwt'];
            } elseif (!empty($_GET['jwt'])) {
                $this->jwtToken = $_GET['jwt'];
            }
            else {
                throw new Exception('JWT token not found in the headers.');
            }
        } else {
            $this->jwtToken = $jwtToken;
        }

        $parts = explode('.', $this->jwtToken);
        if (count($parts) !== 3) {
            throw new Exception('Malformed JWT.');
        }
        $this->jwtPartsEncoded = [
            'header' => $parts[0],
            'payload' => $parts[1],
            'signature' => $parts[2]
        ];

        $this->jwtParts = [
            'header' => json_decode(base64_decode(str_replace(['-', '_'], ['+', '/'], $this->jwtPartsEncoded['header'])), true),
            'payload' => json_decode(base64_decode(str_replace(['-', '_'], ['+', '/'], $this->jwtPartsEncoded['payload'])), true),
            'signature' => $this->jwtPartsEncoded['signature']
        ];

        $this->kid = $this->jwtParts['header']['kid'] ?? throw new Exception('JWT "kid" is missing in the header.');
        if (empty($this->jwtParts['header']['alg'])) {
            throw new Exception('JWT "alg" (algorithm) is missing in the header.');
        }
        if (!isset($this->jwtParts['header']['typ']) || $this->jwtParts['header']['typ'] !== 'JWT') {
            throw new Exception('JWT "typ" (type) must be "JWT".');
        }
        if (!isset($this->jwtParts['payload']['exp']) || $this->jwtParts['payload']['exp'] < time()) {
            throw new Exception('Token has expired.');
        }

        $filePath = $this->keysDirectory . DIRECTORY_SEPARATOR . $this->kid;
        if (is_readable($filePath)) {
            $this->key = file_get_contents($filePath);
            $this->verifyJwtSignature();
        } else if ($this->useRemoteKeyRetrieval) {
            $url = $this->remoteServerUrl . '/' . urlencode($this->kid);
            $headers = ['Authorization' => 'Bearer ' . $this->jwtToken];

            try {
                $response = $this->getWithFallback($url, $headers);
                if ($response['status'] != 200) {
                    throw new Exception("HTTP error " . $response['status'] . " received from " . $url);
                }

                $data = json_decode($response['body'], true, 512, JSON_THROW_ON_ERROR);
                $this->key = $data['key'] ?? throw new Exception('Key not found in remote server response.');$this->key = $data['key'] ?? throw new Exception('Key not found in remote server response.');

                $computedKid = hash('sha256', $this->key);
                if ($computedKid !== $this->kid) {
                    throw new Exception('Public key mismatch.');
                }
                $this->verifyJwtSignature();

                file_put_contents($filePath, $this->key);
            }catch (GuzzleException $e) {
                throw new Exception('Network error during key retrieval: ' . $e->getMessage());
            }
        } else {
            throw new Exception('Key could not be retrieved locally and remote retrieval is not configured.');
        }


        if (!$this->key) {
            throw new Exception('No key available to verify JWT.');
        }
        JWT::decode($this->jwtToken, new JWTKey($this->key, 'RS256'));
    }
    private function getWithFallback($url, $headers) {
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_HEADER, false);

        $httpHeaders = array_map(function ($k, $v) { return "$k: $v"; }, array_keys($headers), $headers);
        curl_setopt($ch, CURLOPT_HTTPHEADER, $httpHeaders);

        curl_setopt($ch, CURLOPT_URL, $url);
        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);

        if (!$response || $httpCode != 200) {
            if (isset($this->config['remote_server_ip'])) {
                $parsedUrl = parse_url($url);
                $originalHost = $parsedUrl['host'];
                $fallbackUrl = str_replace($originalHost, $this->config['remote_server_ip'], $url);
                $httpHeaders[] = "Host: $originalHost";
                curl_setopt($ch, CURLOPT_HTTPHEADER, $httpHeaders);
                curl_setopt($ch, CURLOPT_URL, $fallbackUrl);

                $response = curl_exec($ch);
                $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            }
            if (!$response || $httpCode != 200) {
                curl_close($ch);
                throw new Exception('Failed to retrieve key using fallback IP or original URL. HTTP Code: ' . $httpCode . '. Error: ' . curl_error($ch));
            }
        }

        curl_close($ch);
        return ['body' => $response, 'status' => $httpCode];
    }
    private function verifyJwtSignature(): void
    {
        $data = $this->jwtPartsEncoded['header'] . '.' . $this->jwtPartsEncoded['payload'];
        $signature = base64_decode(str_replace(['-', '_'], ['+', '/'], $this->jwtPartsEncoded['signature']));

        if (!str_starts_with($this->key, '-----BEGIN PUBLIC KEY-----')) {
            $publicKey = "-----BEGIN PUBLIC KEY-----\n" . chunk_split($this->key, 64, "\n") . "-----END PUBLIC KEY-----\n";
        } else {
            $publicKey = $this->key;
        }

        if (openssl_verify($data, $signature, $publicKey, OPENSSL_ALGO_SHA256) !== 1) {
            throw new Exception('Invalid JWT signature.');
        }
    }
    public function getLastErrorMessage(): string
    {
        return $this->lastError ?? 'No error';
    }
}