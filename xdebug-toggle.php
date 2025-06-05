<?php

// define('PATH_TO_PHP_INI', 'CHEMIN_VERS_VOTRE_PHP_INI');
define('PATH_TO_PHP_INI', 'E:/EnvDev/PHP_8_4_4/php.ini');
define('REXP_EXTENSION', '(zend_extension\s*=.*?php_xdebug)');

$s = file_get_contents(PATH_TO_PHP_INI);
$replaced = preg_replace('/;' . REXP_EXTENSION . '/', '$1', $s);
$isOn = $replaced != $s;
if (!$isOn) {
    $replaced = preg_replace('/' . REXP_EXTENSION . '/', ';$1', $s);
}
echo 'xdebug is ' . ($isOn ? 'ACTIVE ' : 'INACTIVE ');
file_put_contents(PATH_TO_PHP_INI, $replaced);

// A décommenter une fois symfony installé

// exec('symfony server:stop');
// exec('php bin/console cache:clear');
// exec('symfony server:start');
