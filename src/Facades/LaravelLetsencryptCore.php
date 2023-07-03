<?php

namespace Wovosoft\LaravelLetsencryptCore\Facades;

use Illuminate\Support\Facades\Facade;

class LaravelLetsencryptCore extends Facade
{
    /**
     * Get the registered name of the component.
     *
     * @return string
     */
    protected static function getFacadeAccessor(): string
    {
        return 'laravel-letsencrypt-core';
    }
}
