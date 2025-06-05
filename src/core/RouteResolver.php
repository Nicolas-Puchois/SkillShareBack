<?php

declare(strict_types=1);

namespace App\core;

use App\core\attributes\Route;
use ReflectionClass;

class RouteResolver
{
    public static function getRoutes(): array
    {
        $routes = [];
        $controllersPath = __DIR__ . "/../controller";
        $controllersFiles = glob($controllersPath . '/*Controller.php');
        foreach ($controllersFiles as $controllersFile) {
            $className = "App\\Controller\\" . basename($controllersFile, ".php");
            $reflection = new ReflectionClass($className);

            foreach ($reflection->getMethods() as $method) {
                $attributes = $method->getAttributes(Route::class);

                foreach ($attributes as $attribute) {
                    $route = $attribute->newInstance();
                    $routes[$route->method][$route->path] = [
                        $className,
                        $method->getName()
                    ];
                }
            }
        }
        return $routes;
    }
}
