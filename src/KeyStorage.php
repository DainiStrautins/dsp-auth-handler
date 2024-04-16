<?php

namespace Dainis\AuthHandler;

class KeyStorage
{
    protected $storageDir;

    public function __construct($storageDir = null)
    {
        // Set the storage directory, defaulting to a directory named 'keys' in the current working directory
        $this->storageDir = $storageDir ?? getcwd() . DIRECTORY_SEPARATOR . 'keys';

        // Ensure storage directory exists
        if (!file_exists($this->storageDir)) {
            mkdir($this->storageDir, 0700, true);
        }
    }

    public function storeKey($kid, $key)
    {
        $filePath = $this->getFilePath($kid);
        file_put_contents($filePath, $key);
    }

    public function retrieveKey($kid)
    {
        $filePath = $this->getFilePath($kid);
        // Retrieve the key from the file
        if (file_exists($filePath)) {
            return file_get_contents($filePath);
        }
        return null;
    }

    protected function getFilePath($kid)
    {
        return $this->storageDir . DIRECTORY_SEPARATOR . $kid . '.key';
    }
}