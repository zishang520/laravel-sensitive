<?php

namespace Sydante\LaravelSensitive;

use Sydante\LaravelSensitive\Commands\ClearCache;
use Sydante\LaravelSensitive\Commands\UpdateCache;

class ServiceProvider extends \Illuminate\Support\ServiceProvider
{
    /**
     * Indicates if loading of the provider is deferred.
     *
     * @var bool
     */
    protected $defer = true;

    /**
     * Bootstrap the application services.
     */
    public function boot(): void
    {
        $this->publishes([
            __DIR__ . '/config/sensitive.php' => config_path('sensitive.php'),
        ]);

        if ($this->app->runningInConsole()) {
            $this->commands([
                UpdateCache::class,
                ClearCache::class,
            ]);
        }
    }

    /**
     * Register the application services.
     */
    public function register(): void
    {
        $this->app->singleton(Sensitive::class, function () {
            return new Sensitive(config('sensitive'));
        });
    }

    /**
     * Get the services provided by the provider.
     */
    public function provides(): array
    {
        return [Sensitive::class, 'sensitive'];
    }
}
