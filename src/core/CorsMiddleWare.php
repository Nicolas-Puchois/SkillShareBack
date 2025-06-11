<?php

declare(strict_types=1);

namespace App\core;

class CorsMiddleWare
{
    public function handle()
    {
        header('Access-Control-Allow-Origin: http://localhost:3001');
        header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS');
        header('Access-Control-Allow-Headers: Content-Type, Authorization, X-Requested-With');
        header('Content-Type: application/json; charset=utf-8');

        if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
            http_response_code(200);
            exit();
        }
    }
}
