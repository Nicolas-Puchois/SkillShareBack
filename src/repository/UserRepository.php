<?php

declare(strict_types=1);

namespace App\repository;

use PDO;
use App\model\User;
use App\core\Database;

class UserRepository
{
    private PDO $pdo;

    public function __construct()
    {
        $this->pdo = Database::getConnexion();
    }

    public function save(User $user): bool
    {
        // requête préparé obligatoire!!!!
        $stmt = $this->pdo->prepare("INSERT INTO `user`
        (username, avatar, email, password_hash,roles, created_at)
        VALUES(?,?,?,?,?,?);");
        return $stmt->execute([
            $user->getUsername(),
            $user->getAvatar(),
            $user->getEmail(),
            $user->getPassword(),
            json_encode($user->getRole()),
            $user->getCreatedAt()
        ]);
    }
}
