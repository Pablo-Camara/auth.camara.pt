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
}
