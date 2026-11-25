<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Http;

class AuthController extends Controller
{
    public function register(Request $request): JsonResponse
    {
        $data = $request->validate([
            'name' => 'required|string|min:3|max:255',
            'email' => 'required|email|max:255|unique:users,email',
            'password' => 'required|string|min:8|confirmed',
        ]);

        $user = User::create($data);

        return response()->json([
            'message' => 'Akun berhasil dibuat.',
            'user' => $user,
        ], 201);
    }

    public function login(Request $request): JsonResponse
    {
        $data = $request->validate([
            'email' => 'required|email',
            'password' => 'required|string',
        ]);

        $user = User::where('email', $data['email'])->first();

        if (! $user || ! $user->password || ! Hash::check($data['password'], $user->password)) {
            return response()->json(['message' => 'Email atau kata sandi salah.'], 401);
        }

        return response()->json([
            'message' => 'Login berhasil.',
            'token' => $user->createToken('auth_token')->plainTextToken,
            'user' => $user,
        ]);
    }

    public function google(Request $request): JsonResponse
{
    $request->validate(['id_token' => 'required|string']);

    $res = Http::post(
        'https://identitytoolkit.googleapis.com/v1/accounts:lookup?key=' . config('services.firebase.api_key'),
        ['idToken' => $request->input('id_token')]
    );

    $fb = $res->json('users.0');

    if ($res->failed() || ! $fb || empty($fb['email'])) {
        return response()->json(['message' => 'Token Google tidak valid.'], 401);
    }

    $isGoogle = collect($fb['providerUserInfo'] ?? [])
        ->contains(fn ($p) => ($p['providerId'] ?? '') === 'google.com');

    if (! $isGoogle || ! ($fb['emailVerified'] ?? false)) {
        return response()->json(['message' => 'Akun Google tidak valid atau belum terverifikasi.'], 422);
    }

    $user = User::where('google_id', $fb['localId'])
        ->orWhere('email', $fb['email'])
        ->first();

    if (! $user) {
        $user = new User([
            'name' => $fb['displayName'] ?? $fb['email'],
            'email' => $fb['email'],
        ]);
    }

    $user->google_id = $user->google_id ?: $fb['localId'];
    $user->avatar = $user->avatar ?: ($fb['photoUrl'] ?? null);
    $user->email_verified_at = $user->email_verified_at ?: now();
    $user->save();

    return response()->json([
        'message' => 'Berhasil masuk dengan Google.',
        'token' => $user->createToken('auth_token')->plainTextToken,
        'user' => $user,
    ]);
}
}