<?php

namespace Wovosoft\LaravelLetsencryptCore;

use Illuminate\Support\ServiceProvider;

class LaravelLetsencryptCoreServiceProvider extends ServiceProvider
{
    /**
     * Perform post-registration booting of services.
     *
     * @return void
     */
    public function boot(): void
    {
        if ($this->app->runningInConsole()) {
            $this->bootForConsole();
        }
    }

    /**
     * Register any package services.
     *
     * @return void
     */
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__ . '/../config/laravel-letsencrypt-core.php', 'laravel-letsencrypt-core');

        //Register the service the package provides.
        $this->app->singleton('laravel-letsencrypt-core', function ($app) {
            return new LaravelLetsencryptCore();
        });
    }

    /**
     * Get the services provided by the provider.
     *
     * @return array
     */
    public function provides(): array
    {
        return ['laravel-letsencrypt-core'];
    }

    /**
     * Console-specific booting.
     *
     * @return void
     */
    protected function bootForConsole(): void
    {
        // Publishing the configuration file.
        $this->publishes([
            __DIR__ . '/../config/laravel-letsencrypt-core.php' => config_path('laravel-letsencrypt-core.php'),
        ], 'laravel-letsencrypt-core.config');


        // Registering package commands.
        $this->commands([
//            TypescriptModelTransformer::class,
        ]);
    }
}
