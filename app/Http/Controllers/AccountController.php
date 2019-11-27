<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;

class AccountController extends Controller
{
    public function __construct()
    {
        $this->middleware('auth:api');
    }

    public function activate(Request $request)
    {
        return response()->json([
            "success" => true
        ]);
    }

}
