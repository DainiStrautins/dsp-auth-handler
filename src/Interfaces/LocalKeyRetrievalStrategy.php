<?php

namespace Dainis\AuthHandler\Interfaces;

class LocalKeyRetrievalStrategy implements KeyRetrievalStrategyInterface
{
    private string $keysDirectory;

    public function __construct(string $keysDirectory)
    {
        $this->keysDirectory = $keysDirectory;
    }

    public function retrieveKey(string $kid): ?string
    {
        $filePath = $this->keysDirectory . DIRECTORY_SEPARATOR . $kid;

        return is_readable($filePath) ? file_get_contents($filePath) : null;
    }
}