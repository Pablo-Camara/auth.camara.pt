<?php

namespace App\Helpers\Auth;

use Carbon\Carbon;
use Laravel\Sanctum\PersonalAccessToken;

class AuthValidator {

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
    public static function validateAuthCookieDecryptedContent($authCookieDecryptedContent) : bool
    {
        // is the auth cookie decrypted content valid ?
        if (
            !is_array($authCookieDecryptedContent)
            ||
            empty($authCookieDecryptedContent['auth_token'])
            ||
            !isset($authCookieDecryptedContent['guest'])
            ||
            !isset($authCookieDecryptedContent['user_id'])
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
    public static function validateAuthToken(?string $authToken) : bool {

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
