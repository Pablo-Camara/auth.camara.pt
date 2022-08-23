<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Models\User;
use Illuminate\Support\Facades\Hash;
use Illuminate\Validation\ValidationException;

class AuthenticationController extends Controller
{
    /**
     * Validates user credentials and generates authentication token
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\Response
     */
    public function loginAttempt(Request $request)
    {
        $request->validate([
            'email' => 'required|email',
            'password' => 'required',
            'device_name' => 'required',
        ]);

        $user = User::where('email', $request->email)->first();

        if (! $user || ! Hash::check($request->password, $user->password)) {
            throw ValidationException::withMessages([
                'email' => ['The provided credentials are incorrect.'], //TODO: translations
            ]);
        }

        //TODO: pass (array)abilities in 2nd param
        //TODO: pass (DateTimeInterface)expiresAt in 3rd param
        //TODO: on Success, set encrypted cookie with the token, send back 'success'
        return $user->createToken($request->device_name)->plainTextToken;
    }
}
