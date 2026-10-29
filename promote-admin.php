<?php
declare(strict_types=1);

if (PHP_SAPI !== 'cli') {
    http_response_code(404);
    exit(1);
}

require_once __DIR__ . '/config/database.php';
require_once __DIR__ . '/src/db.php';

$email = $argv[1] ?? '';
if (!is_string($email) || filter_var($email, FILTER_VALIDATE_EMAIL) === false || strlen($email) > 254) {
    fwrite(STDERR, "Usage: php promote-admin.php user@example.com\n");
    exit(2);
}

$statement = db()->prepare('UPDATE users SET role = :role WHERE email = :email');
$statement->execute([
    'role' => 'admin',
    'email' => strtolower(trim($email)),
]);

if ($statement->rowCount() === 0) {
    $checkUser = db()->prepare('SELECT id FROM users WHERE email = :email LIMIT 1');
    $checkUser->execute(['email' => strtolower(trim($email))]);
    if ($checkUser->fetch() === false) {
        fwrite(STDERR, "No user found with that email address.\n");
        exit(1);
    }
}

fwrite(STDOUT, "Admin role granted to {$email}.\n");
