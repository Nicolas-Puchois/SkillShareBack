<?php

declare(strict_types=1);

namespace App\services;

class MailService
{

    public static function sendEmailVerification(string $email, string $token): void
    {
        $link = "http://localhost:3001/verify-email?token=" . $token;
        $subject = "Verify Your Email Address";
        $message = "
        <html>
        <head>
            <title>Email Verification</title>
        </head>
        <body style='font-family: Arial, sans-serif; background-color: #f9f9f9; padding: 20px;'>
            <table width='100%' cellpadding='0' cellspacing='0' border='0' style='max-width: 600px; margin: auto; background-color: #ffffff; padding: 30px; border-radius: 8px; box-shadow: 0 0 10px rgba(0,0,0,0.05);'>
                <tr>
                    <td style='text-align: center;'>
                        <h2 style='color: #333;'>Welcome to ShareSkill!</h2>
                    </td>
                </tr>
                <tr>
                    <td style='padding: 20px 0; color: #555; font-size: 16px;'>
                        <p>Dear User,</p>
                        <p>Thank you for signing up. Please confirm your email address by clicking the button below:</p>
                        <p style='text-align: center; margin: 30px 0;'>
                            <a href='{$link}' style='background-color: #007bff; color: #fff; padding: 12px 24px; text-decoration: none; border-radius: 5px; display: inline-block;'>Verify Email</a>
                        </p>
                        <p>If you did not create an account, please ignore this message.</p>
                        <p>Thank you,<br>The ShareSkill Team</p>
                    </td>
                </tr>
                <tr>
                    <td style='text-align: center; font-size: 12px; color: #999; padding-top: 20px;'>
                        © " . date('Y') . " ShareSkill. All rights reserved.
                    </td>
                </tr>
            </table>
        </body>
        </html>
        ";

        // Correct headers
        $headers = "MIME-Version: 1.0\r\n";
        $headers .= "Content-type: text/html; charset=UTF-8\r\n";
        $headers .= "From: ShareSkill <noreply@shareskill.com>\r\n";

        // Send the email
        mail($email, $subject, $message, $headers);
    }




    /**
     * Envoie un lien de réinitialisation du mot de passe
     * @param string $email
     * @param string $token
     */
    public static function sendPasswordResetEmail(string $email, string $token): void
    {
        $link = "http://localhost:3001/reset-password?token=" . urlencode($token);

        $subject = "Réinitialisation de votre mot de passe SkillSwap";
        $message = "Vous avez demandé une réinitialisation de mot de passe. Cliquez ici pour le réinitialiser : $link\n\n";
        $message .= "Si vous n'avez pas demandé cette réinitialisation, ignorez cet email.";

        mail($email, $subject, $message, "From: noreply@skillswap.local");
    }
}
