<?php

namespace Dainis\AuthHandler\Config;

class Config {
    protected $settings = [];

    public function __construct(array $settings) {
        $this->settings = $settings;
    }

    public function get($key) {
        return $this->settings[$key] ?? null;
    }
}
