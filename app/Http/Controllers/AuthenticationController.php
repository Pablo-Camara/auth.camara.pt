<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Models\User;
use Carbon\Carbon;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\Cookie;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\InteractsWithTime;
use Illuminate\Validation\ValidationException;

class AuthenticationController extends Controller
{
    use InteractsWithTime;
    /**
     * Authenticates the user
     * if no auth token cookie, creates guest user and generates guest token
     * if auth token cookie, decrypt it and return the current user token
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Illuminate\Http\Response  $response
     * @return \Illuminate\Http\Response
     */
    public function authenticationAttempt(Request $request, Response $response)
    {
        $config = config('session');

        $authCookie = Cookie::get($config['auth_token_cookie_name']);

        if (!is_null($authCookie)) {
            $authCookie = decrypt($authCookie);

            if (
                !is_array($authCookie)
             ) {
                //invalid auth cookie data
                //must be an array
                return new Response(
                    '',
                    403
                );
            }

            $response->setContent([
                'at' => $authCookie['auth_token']
            ]);

            return $response;
        }

        $user = new User(['guest' => 1]);
        $user->save();

        $guestTokenExpirationDatetime = Carbon::now()->addRealMinutes(
            $config['auth_token_cookie_lifetime']
        );

        $userToken = $user->createToken(
            'guest_token',
            ['guest'],
            $guestTokenExpirationDatetime
        )->plainTextToken;

        $response->setContent([
            'at' => $userToken
        ]);

        $authCookie = Cookie::make(
            $config['auth_token_cookie_name'],
            encrypt([
                'auth_token' => $userToken,
                'guest' => 1,
                'user_id' => $user->id
            ]),
            $config['auth_token_cookie_lifetime'],
            $config['path'],
            $config['domain'],
            $config['secure'],
            false,
            false,
            $config['same_site'] ?? null
        );

        return $response
            ->withCookie($authCookie);
    }

    /**
     * Validates user credentials and generates authentication token
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Illuminate\Http\Response  $response
     * @return \Illuminate\Http\Response
     */
    public function loginAttempt(Request $request, Response $response)
    {
        $config = config('session');

        $authCookie = Cookie::get($config['auth_token_cookie_name']);

        if (
            !is_null($authCookie)
         ) {
            $authCookie = decrypt($authCookie);

            if (
                !is_array($authCookie)
             ) {
                //invalid auth cookie data
                //must be an array
                return new Response(
                    '',
                    403
                );
            }
        }

        $request->validate([
            'email' => 'required|email',
            'password' => 'required'
        ]);

        $user = User::where('email', $request->email)->first();

        if (!$user || ! Hash::check($request->password, $user->password)) {
            throw ValidationException::withMessages([
                //TODO: translations
                'email' => ['The provided credentials are incorrect.'],
            ]);
        }

        $userAbilities = $user->abilities->all();
        $userAbilities = array_map(function($ability){
            return $ability['name'];
        }, $userAbilities);
        $userAbilities = array_merge(['logged_in'], $userAbilities);

        $userTokenExpirationDatetime = Carbon::now()->addRealMinutes(
            $config['auth_token_cookie_lifetime']
        );

        $userToken = $user->createToken(
            'stay_logged_in_token',
            $userAbilities,
            $userTokenExpirationDatetime
        )->plainTextToken;

        // it is a guest logging in
        // associate guest user to logged in user
        if (
            (
                isset($authCookie['guest'])
                &&
                $authCookie['guest'] === 1
            )
            &&
            (
                !empty($authCookie['user_id'])
                &&
                is_integer($authCookie['user_id'])
            )
        ) {
            $user->guestUsers()->attach($authCookie['user_id']);
        }

        $authCookie = Cookie::make(
            $config['auth_token_cookie_name'],
            encrypt([
                'auth_token' => $userToken,
                'guest' => 0,
                'user_id' => $user->id
            ]),
            $config['auth_token_cookie_lifetime'],
            $config['path'],
            $config['domain'],
            $config['secure'],
            false,
            false,
            $config['same_site'] ?? null
        );

        // forget 'guest' authentication cookie/token
        Cookie::forget($config['auth_token_cookie_name']);


        return $response
            ->setContent([
                'at' => $userToken
            ])
            ->withCookie($authCookie);
    }
}
