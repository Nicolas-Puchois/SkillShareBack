<?php

declare(strict_types=1);

namespace App\controller;

use DateTime;
use Exception;
use App\model\User;
use App\services\MailService;
use App\core\attributes\Route;
use App\repository\UserRepository;
use App\services\FileUploadService;
use App\services\JWTService;

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
                    'success' => true,
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

        try {
            $data = json_decode(file_get_contents('php://input'), true);
            if (!$data) throw new Exception('JSON invalide');

            $userRepository = new UserRepository();
            if ($userRepository->findUserByUsername($data['username']) && $userRepository->findUserByEmail($data['email'])) {
                throw new Exception("Un compte a déjà été crée avec cet username et cette adresse email.");
            } elseif ($userRepository->findUserByEmail($data['email'])) {
                throw new Exception('Cette adresse email est déjà utilisée !');
            } elseif ($userRepository->findUserByUsername($data['username'])) {
                throw new Exception("Ce nom d'utilisateur est déjà utilisée !");
            };

            $emailToken = bin2hex(random_bytes(32));

            $userData = [
                "username" => $data['username'] ?? '',
                "email" => $data['email'] ?? '',
                "password" => password_hash($data["password"], PASSWORD_BCRYPT),
                "avatar" => $data['avatar'] ?? "avatar_par_defaut.png",
                "email_token"  => $emailToken
            ];

            // création user
            $user = new User($userData);
            $user->setCreatedAt((new DateTime())->format('Y-m-d H:i:s'));
            $saved = $userRepository->save($user);

            if (!$saved) throw new Exception('erreur lors de la sauvegarde');

            if (!$user->getEmailToken()) throw new Exception('Erreur lors de l génération du token de vérification');

            MailService::sendEmailVerification($user->getEmail(), $user->getEmailToken());

            echo json_encode([
                'success' => true,
                'message' => 'Inscription réussie ! Veuillez vérifier vos email.' . json_encode($data)
            ]);
        } catch (\Exception $e) {
            error_log('Erreur inscription: ' . $e->getMessage());
            http_response_code(400);
            echo json_encode([
                "success" => false,
                "error" => $e->getMessage()
            ]);
        }
    }




    #[Route('/api/login', 'POST')]
    public function login()
    {
        try {
            $data = json_decode(file_get_contents('php://input'), true);
            if (!$data) throw new Exception('JSON invalide');
            $userRepository = new UserRepository();
            $user = $userRepository->findUserByEmail($data['email']);
            if (!$user) throw new Exception('Email ou mot de passe incorrect !');
            if (!password_verify($data['password'], $user->getPassword()))  throw new Exception('Email ou mot de passe incorrect');
            if (!$user->getIsVerified()) throw new Exception("Veuillez vérifier votre email avant de  vous connecter ");

            // générer le token JWT
            $token = JWTService::generate([
                "id_user" => $user->getId(),
                "role" => $user->getRoles(),
                "email" => $user->getEmail()
            ]);

            echo json_encode([
                'success' => true,
                'token' => $token,
                'user' => [
                    'avatar' => $user->getAvatar(),
                    'username' => $user->getUsername()
                ]
            ]);
        } catch (\Exception $e) {
            error_log('Erreur inscription: ' . $e->getMessage());
            http_response_code(400);
            echo json_encode([
                "success" => false,
                "error" => $e->getMessage()
            ]);
        }
    }




    #[Route('/api/verify-email', 'GET')]
    public function verifyEmail()
    {
        try {
            $token = $_GET['token'] ?? null;

            if (!$token) throw new Exception('Token manquant!');

            $userRepository = new UserRepository();
            $user = $userRepository->findUserByToken($token);

            if (!$user) throw new Exception('Utilisateur introuvable');

            $user->setEmailToken(null);
            $user->setIsVerified(true);

            $updated = $userRepository->update($user);


            if (!$updated) throw new Exception('erreur lors de la mise a jour');
            echo json_encode([
                'success' => true,
                'message' => 'Email vérifié avec succès!'
            ]);
        } catch (\Exception $e) {
            error_log('Erreur inscription: ' . $e->getMessage());
            http_response_code(400);
            echo json_encode([
                "success" => false,
                "error" => $e->getMessage()
            ]);
        }
    }
}
