<?php

namespace App\Helpers\Responses;

use Illuminate\Http\Response;

class AuthResponses {


    public static function notAuthenticated() {
        return response()->json([
            //TODO: translate msg str
            'error_id' => 'not_authenticated',
            // TODO: translate
            'message' => 'Must authenticate first!'
        ], Response::HTTP_UNAUTHORIZED);
    }


    public static function incorrectCredentials() {
        return response()->json([
            //TODO: translate msg str
            'error_id' => 'incorrect_credentials',
            // TODO: translate
            'message' => 'Email or password is invalid'
        ], Response::HTTP_UNAUTHORIZED);
    }
}
