<?php

namespace Wovosoft\LaravelLetsencryptCore\Data;

use Illuminate\Support\Collection;

/**
 * @property-read string $keyChange
 * @property-read array $meta
 * @property-read string $newAccount
 * @property-read string $newNonce
 * @property-read string $newOrder
 * @property-read string $renewalInfo
 * @property-read string $revokeCert
 */
class Directories
{
    protected array $properties = [];

    public function __construct(\stdClass $directories)
    {
        foreach (array_keys((array)$directories) as $key) {
            $this->properties[$key] = $directories->$key;
        }
    }

    public function getProperties(): array
    {
        return $this->properties;
    }

    public function __get(string $name)
    {
        return $this->properties[$name];
    }

    public function __toString(): string
    {
        return json_encode($this->properties, JSON_PRETTY_PRINT);
    }

    public function toArray(): array
    {
        return $this->properties;
    }

    public function toCollection(): Collection
    {
        return collect($this->properties);
    }
}
