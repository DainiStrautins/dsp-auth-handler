<?php

namespace Dainis\AuthHandler\Interfaces;

interface KeyRetrievalStrategyInterface
{
    public function retrieveKey(string $kid): ?string;
}