<?php
declare(strict_types=1);

error_reporting(E_ALL);
ini_set('display_errors', '1');
ini_set('display_startup_errors', '1');

require_once __DIR__ . '/config/database.php';
require_once __DIR__ . '/src/db.php';
require_once __DIR__ . '/src/helpers.php';
require_once __DIR__ . '/src/csrf.php';

if (session_status() !== PHP_SESSION_ACTIVE) {
    if (headers_sent($file, $line)) {
        throw new RuntimeException("Session must start before output; output began in {$file}:{$line}.");
    }

    $https = in_array(strtolower((string) ($_SERVER['HTTPS'] ?? '')), ['on', '1'], true);

    session_name('SWDSESSID');
    ini_set('session.use_strict_mode', '1');
    ini_set('session.use_only_cookies', '1');
    session_set_cookie_params([
        'lifetime' => 0,
        'path' => '/',
        'secure' => $https,
        'httponly' => true,
        'samesite' => 'Lax',
    ]);

    if (!session_start()) {
        throw new RuntimeException('Unable to start the authentication session.');
    }
}
