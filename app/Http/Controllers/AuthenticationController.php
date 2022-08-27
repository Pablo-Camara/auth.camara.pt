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
use Laravel\Sanctum\PersonalAccessToken;

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

            $isAuthCookieValid = $this->validateAuthCookie($authCookie);
            $isAuthTokenValid = false;

            if($isAuthCookieValid) {
                $isAuthTokenValid = $this->validateAuthToken($authCookie['auth_token']);
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

        if (
            !is_null($authCookie)
        ) {
            $authCookie = decrypt($authCookie);

            $isAuthCookieValid = $this->validateAuthCookie($authCookie);
            $isAuthTokenValid = false;

            if($isAuthCookieValid) {
                $isAuthTokenValid = $this->validateAuthToken($authCookie['auth_token']);
            }

            if (
                $isAuthCookieValid && $isAuthTokenValid
            ) {
                // if auth cookie is valid
                // if auth token is valid / not expired
                // and the auth cookie is for a logged in user (non guest)
                // lets tell the user he is already logged in
                // and that his request is not acceptable!

                if ($authCookie['guest'] === 0) {
                    return $response
                        ->setContent([
                            //TODO: translate msg str
                            'message' => 'already logged in'
                        ])
                        ->setStatusCode(406);
                }
            } else {
                // auth cookie or token is invalid
                // lets forbid the login. Must authenticate as guest first.

                // and lets forget this invalid auth cookie and/or token
                Cookie::forget($config['auth_token_cookie_name']);

                return $response
                    ->setContent([
                        //TODO: translate msg str
                        'message' => 'Unauthenticated'
                    ])
                    ->setStatusCode(401);
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
                'at' => $userToken
            ])
            ->withCookie($authCookie);
    }


    /**
     * Validate Auth Cookie decrypted content
     * make sure content is an array
     * make sure array has an auth_token
     * make sure array has a guest flag
     * make sure array has an user_id
     *
     * @param mixed $authCookie
     * @return bool
     */
    private function validateAuthCookie($authCookie) : bool
    {
        // is the auth cookie decrypted content valid ?
        if (
            !is_array($authCookie)
            ||
            empty($authCookie['auth_token'])
            ||
            !isset($authCookie['guest'])
            ||
            !isset($authCookie['user_id'])
            ) {
            //invalid auth cookie data
            //must be an array
            //must contain auth_token
            //must contain guest flag
            //must contain user_id

            return false;
        }

        return true;
    }


    /**
     * Validate an Auth token
     * makes sure token exists
     * makes sure token is not expired
     *
     * @param ?string $authToken
     * @return bool
     */
    private function validateAuthToken(?string $authToken) : bool {

        // an empty or null string is an invalid token..
        if (empty($authToken)) {
            return false;
        }

        // does the auth_token still exist?
        $personalAccessToken = PersonalAccessToken::findToken(
            $authToken
        );

        if ($personalAccessToken) {
            // is the auth_token still valid / not expired?
            $hasTokenExpired = Carbon::now() >= $personalAccessToken->expires_at;

            // if auth_token exists and is not expired it is valid
            return false === $hasTokenExpired;
        }

        // if it no longer exists it is invalid
        return false;
    }
}
