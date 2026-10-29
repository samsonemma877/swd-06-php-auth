<?php
declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

require_guest();

$errors = [];
$email = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $emailInput = $_POST['email'] ?? '';
    $passwordInput = $_POST['password'] ?? '';
    $email = is_string($emailInput) ? strtolower(trim($emailInput)) : '';
    $password = is_string($passwordInput) ? $passwordInput : '';

    if (!csrf_verify()) {
        http_response_code(403);
        $errors[] = 'Your form session expired or could not be verified. Please refresh the page and try again.';
    } else {
        $statement = db()->prepare(
            'SELECT id, name, email, password_hash, role FROM users WHERE email = :email LIMIT 1'
        );
        $statement->execute(['email' => $email]);
        $user = $statement->fetch();

        if (
            $user === false
            || !is_string($user['password_hash'])
            || !password_verify($password, $user['password_hash'])
        ) {
            $errors[] = 'Invalid email or password';
        } elseif (!is_string($user['role']) || $user['role'] === '') {
            throw new UnexpectedValueException('The user account has no valid role.');
        } else {
            if (!session_regenerate_id(true)) {
                throw new RuntimeException('Unable to rotate the session identifier after login.');
            }

            if (password_needs_rehash($user['password_hash'], PASSWORD_DEFAULT)) {
                $passwordHash = password_hash($password, PASSWORD_DEFAULT);
                if (!is_string($passwordHash)) {
                    throw new RuntimeException('Unable to securely re-hash the password.');
                }
                $update = db()->prepare(
                    'UPDATE users SET password_hash = :password_hash, last_login_at = CURRENT_TIMESTAMP WHERE id = :id'
                );
                $update->execute([
                    'password_hash' => $passwordHash,
                    'id' => $user['id'],
                ]);
            } else {
                $update = db()->prepare(
                    'UPDATE users SET last_login_at = CURRENT_TIMESTAMP WHERE id = :id'
                );
                $update->execute(['id' => $user['id']]);
            }

            $_SESSION['user_id'] = (int) $user['id'];
            $_SESSION['user_role'] = $user['role'];
            $_SESSION['user_name'] = $user['name'];
            $_SESSION['user_email'] = $user['email'];
            $_SESSION['last_activity_at'] = time();
            unset($_SESSION['_csrf_token']);

            $destination = take_intended_url() ?? 'dashboard.php';
            redirect($destination);
        }
    }
}

$email = old('email', $email);
unset($_SESSION['_old']);
$infoMessage = flash('info');
$successMessage = flash('success');
?>
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Sign in</title>
    <link rel="stylesheet" href="assets/auth.css">
</head>
<body>
<main class="auth-page">
    <section class="auth-card" aria-labelledby="page-title">
        <div class="auth-heading">
            <p class="eyebrow">Welcome back</p>
            <h1 id="page-title">Sign in</h1>
            <p class="muted">Use your email and password to continue.</p>
        </div>

        <?php foreach ([$infoMessage, $successMessage] as $message): ?>
            <?php if ($message !== null): ?>
                <div class="notice notice-success" role="status"><?= e($message) ?></div>
            <?php endif; ?>
        <?php endforeach; ?>

        <?php if ($errors !== []): ?>
            <div class="notice notice-error" role="alert">
                <ul>
                    <?php foreach ($errors as $error): ?>
                        <li><?= e($error) ?></li>
                    <?php endforeach; ?>
                </ul>
            </div>
        <?php endif; ?>

        <form method="post" action="login.php">
            <?= csrf_field() ?>
            <div class="form-field">
                <label for="email">Email address</label>
                <input id="email" name="email" type="email" autocomplete="email" maxlength="254" required value="<?= e($email) ?>">
            </div>
            <div class="form-field">
                <label for="password">Password</label>
                <input id="password" name="password" type="password" autocomplete="current-password" required>
            </div>
            <button class="button" type="submit">Sign in</button>
        </form>
        <p class="muted auth-footer">New here? <a href="register.php">Create an account</a></p>
    </section>
</main>
</body>
</html>
