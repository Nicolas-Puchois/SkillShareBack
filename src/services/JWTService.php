<?php

declare(strict_types=1);

namespace App\services;

use Exception;

class JWTService
{
    public static ?string $key = null;

    public static function initKey(): void
    {
        if (self::$key == null) {
            self::$key = $_ENV["JWT_SECRET_KEY"] ?? '';
            if (empty(self::$key)) throw new Exception("Clé secrète non défini dans la configuration actuelle (JWT_SECRET_KEY)");
        }
    }

    public static function generate(array $payload): string
    {

        self::initKey();
        $headers = [
            'type' => "JWT",
            'alg' => 'HS256'
        ];

        $payload['exp'] = time() + (24 * 60 * 60);

        $base64Header = self::base64url_encode(json_encode($headers));
        $base64Payload = self::base64url_encode(json_encode($payload));

        // création de la signature 
        $signature = hash_hmac("sha256", $base64Header . '.' . $base64Payload, self::$key, true);
        $base64Signature = self::base64url_encode($signature);

        return $base64Header . '-' . $base64Payload . '-' . $base64Signature;
    }


    private static function base64url_encode(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }
}
