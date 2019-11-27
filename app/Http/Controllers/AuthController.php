<?php

namespace App\Http\Controllers;

use App\User;
use Illuminate\Auth\Events\Registered;
use Illuminate\Foundation\Auth\AuthenticatesUsers;
use Illuminate\Support\Facades\Auth;
use App\Http\Controllers\Controller;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;
use Illuminate\Http\Request;
use Psy\Util\Str;

class AuthController extends Controller
{

    use AuthenticatesUsers;

    /**
     * Create a new AuthController instance.
     *
     * @return void
     */
    public function __construct()
    {
        $this->middleware('auth:api', ['except' => [
            'apiLogin', 'register', 'registerSendTAC', 'registerCheckTAC'
        ]]);
    }

    public function username()
    {
        return 'phone';
    }

    /**
     * Get a JWT via given credentials.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function apiLogin(Request $request)
    {
        $errors = $this->authValidator($request->all())->errors();

        if(count($errors)) {
            return response(['error' => $errors->first()], 401);
        }

        $credentials = request(['phone', 'password']);

        if (! $token = Auth::guard()->attempt($credentials)) {
            return response()->json([
                'success' => false,
                'error' => 'Login failed'
            ], 401);
        }

        return $this->respondWithToken($token);
    }

    /**
     * Get the authenticated User.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function me()
    {
        return response()->json(auth()->user());
    }

    /**
     * Log the user out (Invalidate the token).
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function logout()
    {
        auth()->logout();

        return response()->json([
            'success' => true,
            'message' => 'Successfully logged out'
        ]);
    }

    /**
     * Refresh a token.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function refresh()
    {
        return $this->respondWithToken(auth()->refresh());
    }

    /**
     * Get the token array structure.
     *
     * @param  string $token
     *
     * @return \Illuminate\Http\JsonResponse
     */
    protected function respondWithToken($token)
    {
        return response()->json([
            'access_token' => $token,
            'token_type' => 'bearer',
            'expires_in' => auth()->factory()->getTTL() * 60
        ]);
    }


    /**
     * Get a validator for an incoming auth request.
     *
     * @param  array  $data
     * @return \Illuminate\Contracts\Validation\Validator
     */
    protected function authValidator(array $data)
    {
        return Validator::make($data, [
            'phone' => 'required|string|max:255',
            'password' => 'required|string',
        ]);
    }

    /**
     * Get a validator for an incoming registration request.
     *
     * @param  array  $data
     * @return \Illuminate\Contracts\Validation\Validator
     */
    protected function registerValidator(array $data)
    {
        return Validator::make($data, [
            'name' => 'required|string|max:255',
            'email' => 'required|string|email|max:255|unique:Users',
            'password' => 'required|string|min:6|confirmed',
        ]);
    }



    /**
     * Create a new user instance after a valid registration.
     *
     * @param  array  $data
     * @return \App\User
     */
    protected function registerCreate(array $data)
    {
        return User::create([
            'phone' => $data['phone'],
            'password' => Hash::make($data['password'])
        ]);
    }

    public function register(Request $request)
    {
        $errors = $this->registerValidator($request->all())->errors();
        if(count($errors)) {
            return response([
                'success' => false,
                'message' => $errors->first()
            ], 401);
        }

        event(new Registered($user = $this->registerCreate($request->all())));

        $this->guard()->login($user);

        return response()->json([
            'success' => true
        ], 201);
    }

    public function registerSendTAC(Request $request)
    {
        $errors = Validator::make($request->all(), ['phone' => 'required|string|max:255'])->errors();
        if(count($errors)) {
            return response([
                'success' => false,
                'message' => $errors->first()
            ], 401);
        }

        return response()->json([
            'success' => true,
            'phoneNumber' => $request->phone
        ]);
    }

    public function registerCheckTAC(Request $request)
    {
        $errors = Validator::make($request->all(), [
            'phone' => 'required|string|max:255|unique:users',
            'tac' => 'required|integer|min:100000|max:999999'
        ])->errors();

        if(count($errors)) {
            return response([
                'success' => false,
                'message' => $errors->first()
            ], 401);
        }

        if ($request->tac == '123456') {

//            $password =\Illuminate\Support\Str::random(6);
            $password = '123456';

            event(new Registered($user = $this->registerCreate([
                'phone' => $request->phone,
                'password' => $password
            ])));

            $token = Auth::guard()->attempt([
                'phone' => $request->phone,
                'password' => $password
            ]);

            return response()->json([
                'success' => true,
                'phoneNumber' => $request->phone,
                'token' => $token
            ]);
        } else {
            return response()->json([
                'success' => false,
                'message' => 'Wrong code',
                'phoneNumber' => $request->phone
            ]);
        }



    }
}