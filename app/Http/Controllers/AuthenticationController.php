<?php

namespace App\Http\Controllers;

use App\Helpers\Auth\AuthValidator;
use Illuminate\Http\Request;
use App\Models\User;
use Carbon\Carbon;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\Cookie;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\InteractsWithTime;
use App\Helpers\Responses\AuthResponses;

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

        if (
            !is_null($authCookie)
        ) {
            $authCookie = decrypt($authCookie);

            $isAuthCookieValid = AuthValidator::validateAuthCookieDecryptedContent($authCookie);
            $isAuthTokenValid = false;

            if($isAuthCookieValid) {
                $isAuthTokenValid = AuthValidator::validateAuthToken($authCookie['auth_token']);
            }

            if ($isAuthCookieValid && $isAuthTokenValid) {
                // if auth cookie is valid
                // if auth token is valid / not expired
                // send the auth token from the cookie
                $response->setContent([
                    'at' => $authCookie['auth_token'],
                    'guest' => $authCookie['guest']
                ]);

                return $response;
            }

            // if auth cookie is invalid
            // or
            // if auth token is expired or invalid
            // forget the cookie
            Cookie::forget($config['auth_token_cookie_name']);
        }

        // creates new guest user
        $user = new User(['guest' => 1]);
        $user->save();

        // creates new guest token
        $guestTokenExpirationDatetime = Carbon::now()->addRealMinutes(
            $config['auth_token_cookie_lifetime']
        );

        $userToken = $user->createToken(
            'guest_token',
            ['guest'],
            $guestTokenExpirationDatetime
        )->plainTextToken;

        $response->setContent([
            'at' => $userToken,
            'guest' => 1
        ]);

        // creates new authCookie
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

        // send response with the new cookie
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

        // when logging in, users must always have an Auth Cookie (with guest token)
        if (is_null($authCookie)) {
            return AuthResponses::notAuthenticated();
        }

        $authCookie = decrypt($authCookie);

        $isAuthCookieValid = AuthValidator::validateAuthCookieDecryptedContent($authCookie);
        $isAuthTokenValid = false;

        if($isAuthCookieValid) {
            $isAuthTokenValid = AuthValidator::validateAuthToken($authCookie['auth_token']);
        }

        if (
            $isAuthCookieValid && $isAuthTokenValid
        ) {
            // if auth cookie is valid
            // if auth token is valid / not expired
            // and the auth cookie is for a logged in user (non guest)
            // the user is already logged in
            // lets return the current auth cookie data

            if ($authCookie['guest'] === 0) {
                return $response
                        ->setContent([
                            'at' => $authCookie['auth_token'],
                            'guest' => 0
                        ]);
            }
        } else {
            // auth cookie or token is invalid
            // lets forbid the login. Must authenticate as guest first.

            // and lets forget this invalid auth cookie and/or token
            Cookie::forget($config['auth_token_cookie_name']);

            return AuthResponses::notAuthenticated();
        }

        $request->validate([
            'email' => 'required|email',
            'password' => 'required'
        ]);

        $user = User::where('email', $request->email)->first();

        if (!$user || ! Hash::check($request->password, $user->password)) {
            return AuthResponses::incorrectCredentials();
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

        // it is always a guest that is logging in
        // associate guest user to logged in user
        $user->guestUsers()->attach($authCookie['user_id']);

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
                'at' => $userToken,
                'guest' => 0
            ])
            ->withCookie($authCookie);
    }
}
