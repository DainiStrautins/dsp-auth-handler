<?php

namespace Dainis\AuthHandler;

class Config
{
    public static function get($key, $default = null)
    {
        $config = include 'config.php';  // Assuming your config settings are in the config.php file
        return $config[$key] ?? $default;
    }
}
