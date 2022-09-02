<?php

namespace App\Providers;

use App\Models\Sanctum\PersonalAccessToken;
use Illuminate\Foundation\AliasLoader;
use Illuminate\Support\ServiceProvider;
use Laravel\Sanctum\Sanctum;

class AppServiceProvider extends ServiceProvider
{
    /**
     * Register any application services.
     *
     * @return void
     */
    public function register()
    {
        //
    }

    /**
     * Bootstrap any application services.
     *
     * @return void
     */
    public function boot()
    {
        Sanctum::usePersonalAccessTokenModel(PersonalAccessToken::class);

        // Loader Alias
        $loader = AliasLoader::getInstance();
        $loader->alias(\Laravel\Sanctum\NewAccessToken::class, \App\Models\Sanctum\NewAccessToken::class);
        $loader->alias(\Laravel\Sanctum\Events\TokenAuthenticated::class, \App\Models\Sanctum\Events\TokenAuthenticated::class);
    }
}
