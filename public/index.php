<?php

require_once "../vendor/autoload.php";

$path = explode('/', trim( $_SERVER['REQUEST_URI']));
$views = '/views/';


// SessionController::userSignUp("rusben", "rusben@elpuig.xeill.net", "password");
// die();

SessionController::userLogin("rusben", "password");

print_r($_SESSION);
die();


switch ($path[1]) {
    case '':
    case '/':
        require __DIR__ . $views . 'login.php';
        break;

    case 'admin':      
        require __DIR__ . $views . 'admin.php';
        break;

    case 'not-found':
    default:
        http_response_code(404);
        require __DIR__ . $views . '404.php';
}
