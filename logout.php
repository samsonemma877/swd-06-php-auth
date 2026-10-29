<?php
declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    header('Allow: POST');
    exit('Method not allowed.');
}

if (!csrf_verify()) {
    http_response_code(403);
    exit('Your form session expired or could not be verified. Please refresh the page and try again.');
}

$_SESSION = [];
$cookie = session_get_cookie_params();
if (!setcookie(session_name(), '', [
    'expires' => time() - 42000,
    'path' => $cookie['path'],
    'domain' => $cookie['domain'],
    'secure' => $cookie['secure'],
    'httponly' => $cookie['httponly'],
    'samesite' => $cookie['samesite'],
])) {
    throw new RuntimeException('Unable to expire the session cookie during logout.');
}

if (!session_destroy()) {
    throw new RuntimeException('Unable to destroy the session during logout.');
}

session_id('');
if (!session_start()) {
    throw new RuntimeException('Unable to start a new session after logout.');
}

flash('success', 'You have been signed out.');
redirect('login.php');
