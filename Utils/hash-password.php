<?php
include_once 'utils.php';

function ascii_art()
{
    change_color('cyan');

    echo " _______  _______  _______  _______  _______  _______           _______ _________\n";
    echo "(  ____ )(  ___  )(  ____ \(  ____ \(  ____ \(  ____ )|\     /|(  ____ )\__   __/\n";
    echo "| (    )|| (   ) || (    \/| (    \/| (    \/| (    )|( \   / )| (    )|   ) (\n";
    echo "| (____)|| (___) || (_____ | (_____ | |      | (____)| \ (_) / | (____)|   | |\n";
    echo "|  _____)|  ___  |(_____  )(_____  )| |      |     __)  \   /  |  _____)   | |\n";
    echo "| (      | (   ) |      ) |      ) || |      | (\ (      ) (   | (         | |\n";
    echo "| )      | )   ( |/\____) |/\____) || (____/\| ) \ \__   | |   | )         | |\n";
    echo "|/       |/     \|\_______)\_______)(_______/|/   \__/   \_/   |/          )_(\n";
}
ascii_art();
change_color('white');
echo "-----------------------------------\n";
change_color('blue');
echo "Générateur de hash sécurisé\n";
change_color('white');
echo "-----------------------------------\n\n";

function display_hash_options()
{
    echo "\nChoisissez l'algorithme de hachage :\n";
    echo "1. BCRYPT (recommandé pour la compatibilité)\n";
    echo "2. ARGON2I (plus sécurisé, plus récent)\n";
    echo "3. ARGON2ID (plus sécurisé, plus récent)\n";
    echo "Votre choix [1-3, défaut: 1] : ";
}

function get_hash_options($algo, $cost = null)
{
    switch ($algo) {
        case '2':
            return [
                'algorithm' => PASSWORD_ARGON2I,
                'memory_cost' => 65536,
                'time_cost' => 4,
                'threads' => 1
            ];
        case '3':
            return [
                'algorithm' => PASSWORD_ARGON2ID,
                'memory_cost' => 65536,
                'time_cost' => 4,
                'threads' => 1
            ];
        default:
            return [
                'algorithm' => PASSWORD_BCRYPT,
                'cost' => $cost ?? 10
            ];
    }
}

function ask_continue()
{
    echo "\nVoulez-vous hasher un autre mot de passe ? (o/N) : ";
    $answer = strtolower(trim(fgets(STDIN)));
    return $answer === 'o' || $answer === 'oui';
}

function generate_hash($handle)
{
    echo "Entrez le mot de passe à hasher : ";
    $password = trim(fgets($handle));

    display_hash_options();
    $algo_choice = trim(fgets($handle));

    $hash_options = [];
    if ($algo_choice === '1') {
        echo "Entrez le coût (10-14) [Entrée = 10] : ";
        $cost = trim(fgets($handle));
        if (!is_numeric($cost) || $cost < 10 || $cost > 14) {
            $cost = 10;
        }
        $hash_options = get_hash_options($algo_choice, $cost);
    } else {
        $hash_options = get_hash_options($algo_choice);
    }

    echo "\nGénération du hash en cours";
    for ($i = 0; $i < 3; $i++) {
        echo ".";
        usleep(500000);
    }
    echo "\n";

    $hash = password_hash($password, $hash_options['algorithm'], $hash_options);

    echo "\nVoici votre hash :\n";
    echo "-----------------------------------\n";
    change_color('green');
    echo $hash . "\n";
    change_color('white');
    echo "-----------------------------------\n";

    if ($hash_options['algorithm'] === PASSWORD_BCRYPT) {
        echo "Algorithme : BCRYPT (coût : {$hash_options['cost']})\n";
    } else {
        $algo_name = $hash_options['algorithm'] === PASSWORD_ARGON2I ? "ARGON2I" : "ARGON2ID";
        echo "Algorithme : $algo_name\n";
        echo "Paramètres : Memory: {$hash_options['memory_cost']}KB, Time: {$hash_options['time_cost']}, Threads: {$hash_options['threads']}\n";
    }
    echo "-----------------------------------\n";
}

$handle = fopen("php://stdin", "r");
do {
    generate_hash($handle);
} while (ask_continue());

fclose($handle);
echo "\nMerci d'avoir utilisé PASSCRYPT !\n";
