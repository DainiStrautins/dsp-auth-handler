<?php

namespace Dainis\AuthHandler;

class Config
{
    public static function get($key, $default = null)
    {
        $config = include 'config.php';
        return $config[$key] ?? $default;
    }
}
