<?php

declare(strict_types=1);

namespace App\controller;

use DateTime;
use Exception;
use App\model\User;
use App\core\attributes\Route;
use App\repository\UserRepository;
use App\services\FileUploadService;

class UserController
{
    #[Route('/api/upload-avatar', 'POST')]
    public function uploadAvatar()
    {

        if (!isset($_FILES['avatar'])) throw new Exception('Aucun fichier uploadé!');

        try {
            $filename = FileUploadService::handleAvatarUpload($_FILES['avatar'], __DIR__ . '/../../public/uploads/avatar/');

            // if($user->getAvatar() !== "avatar_par_defaut.png"){
            //     FileUploadService::deleteOldAvatar($user->getAvatar());
            // }
            echo json_encode(
                [
                    'sucess' => true,
                    'message' => "Avatar mis a jour  avec succès",
                    'filename' => $filename
                ]
            );
        } catch (Exception $excep) {
            throw new  Exception("Erreur lors de l'upload : " .  $excep->getMessage());
        }
    }


    #[Route('/api/register', 'POST')]
    public function register()
    {

        $data = json_decode(file_get_contents('php://input'), true);
        if (!$data) throw new Exception('JSON invalide');

        $userData = [
            "username" => $data['username'] ?? '',
            "email" => $data['email'] ?? '',
            "password" => password_hash($data["password"], PASSWORD_BCRYPT),
            // "avatar" => $data['avatar'] ?? '',

        ];

        // création user
        $user = new User($userData);
        $user->setCreatedAt((new DateTime())->format('Y-m-d H:i:s'));
        $userRepository = new UserRepository();

        $saved = $userRepository->save($user);

        if (!$saved) throw new Exception('erreur lors de la sauvegarde');

        echo json_encode([
            'success' => true,
            'message' => 'Inscription réussie ! Veuillez vérifier vos email.' . json_encode($data)
        ]);
    }
}
