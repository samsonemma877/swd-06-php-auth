<?php
declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

$errors = [];
$name = '';
$email = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $nameInput = $_POST['name'] ?? '';
    $emailInput = $_POST['email'] ?? '';
    $passwordInput = $_POST['password'] ?? '';
    $confirmInput = $_POST['confirm_password'] ?? '';

    $name = is_string($nameInput) ? trim($nameInput) : '';
    $email = is_string($emailInput) ? strtolower(trim($emailInput)) : '';
    $password = is_string($passwordInput) ? $passwordInput : '';
    $confirmPassword = is_string($confirmInput) ? $confirmInput : '';
    $_SESSION['_old'] = ['name' => $name, 'email' => $email];

    if (!csrf_verify()) {
        http_response_code(403);
        $errors[] = 'Your form session expired or could not be verified. Please refresh the page and try again.';
    } else {
        if ($name === '') {
            $errors[] = 'Please enter your name.';
        } elseif (strlen($name) > 100) {
            $errors[] = 'Name must be 100 characters or fewer.';
        }

        if (filter_var($email, FILTER_VALIDATE_EMAIL) === false || strlen($email) > 254) {
            $errors[] = 'Enter a valid email address (maximum 254 characters).';
        }

        $passwordLength = preg_match_all('/./us', $password, $passwordCharacters);
        if ($passwordLength === false || $passwordLength < 10) {
            $errors[] = 'Password must be at least 10 characters long.';
        }
        if (preg_match('/\p{L}/u', $password) !== 1 || preg_match('/[0-9]/', $password) !== 1) {
            $errors[] = 'Password must contain at least one letter and one number.';
        }
        if ($password !== $confirmPassword) {
            $errors[] = 'Passwords do not match.';
        }

        if ($errors === []) {
            $pdo = db();
            $emailCheck = $pdo->prepare('SELECT id FROM users WHERE email = :email LIMIT 1');
            $emailCheck->execute(['email' => $email]);

            if ($emailCheck->fetch() !== false) {
                $errors[] = 'An account with that email address already exists.';
            } else {
                $passwordHash = password_hash($password, PASSWORD_DEFAULT);
                if (!is_string($passwordHash)) {
                    throw new RuntimeException('Unable to securely hash the password.');
                }
                $insert = $pdo->prepare(
                    "INSERT INTO users (name, email, password_hash, role, last_login_at) VALUES (:name, :email, :password_hash, 'user', CURRENT_TIMESTAMP)"
                );

                try {
                    $insert->execute([
                        'name' => $name,
                        'email' => $email,
                        'password_hash' => $passwordHash,
                    ]);
                } catch (PDOException $exception) {
                    if ($exception->getCode() !== '23000') {
                        throw $exception;
                    }

                    $emailCheck->execute(['email' => $email]);
                    if ($emailCheck->fetch() === false) {
                        throw $exception;
                    }

                    $errors[] = 'An account with that email address already exists.';
                }

                if ($errors === []) {
                    if (!session_regenerate_id(true)) {
                        throw new RuntimeException('Unable to rotate the session identifier after registration.');
                    }
                    $_SESSION['user_id'] = (int) $pdo->lastInsertId();
                    $_SESSION['user_role'] = 'user';
                    $_SESSION['auth_version'] = 0;
                    $_SESSION['user_name'] = $name;
                    $_SESSION['user_email'] = $email;
                    $_SESSION['last_activity_at'] = time();
                    unset($_SESSION['_old'], $_SESSION['_csrf_token']);

                    flash('success', 'Your account has been created.');
                    redirect('dashboard.php');
                }
            }
        }
    }
}

$name = old('name', $name);
$email = old('email', $email);
unset($_SESSION['_old']);
$successMessage = flash('success');
?>
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Create account</title>
    <link rel="stylesheet" href="assets/auth.css">
</head>
<body>
<main class="auth-page">
    <section class="auth-card" aria-labelledby="page-title">
        <div class="auth-heading">
            <p class="eyebrow">Get started</p>
            <h1 id="page-title">Create your account</h1>
            <p class="muted">Enter your details to get started.</p>
        </div>

        <?php if ($successMessage !== null): ?>
            <div class="notice notice-success" role="status"><?= e($successMessage) ?></div>
        <?php endif; ?>

        <?php if ($errors !== []): ?>
            <div class="notice notice-error" role="alert">
                <p>Please correct the following:</p>
                <ul>
                    <?php foreach ($errors as $error): ?>
                        <li><?= e($error) ?></li>
                    <?php endforeach; ?>
                </ul>
            </div>
        <?php endif; ?>

        <form method="post" action="register.php">
            <?= csrf_field() ?>
            <div class="form-field">
                <label for="name">Name</label>
                <input id="name" name="name" type="text" autocomplete="name" maxlength="100" required value="<?= e($name) ?>">
            </div>
            <div class="form-field">
                <label for="email">Email address</label>
                <input id="email" name="email" type="email" autocomplete="email" maxlength="254" required value="<?= e($email) ?>">
            </div>
            <div class="form-field">
                <label for="password">Password</label>
                <input id="password" name="password" type="password" autocomplete="new-password" required>
                <small>At least 10 characters, including a letter and a number.</small>
            </div>
            <div class="form-field">
                <label for="confirm_password">Confirm password</label>
                <input id="confirm_password" name="confirm_password" type="password" autocomplete="new-password" required>
            </div>
            <button class="button" type="submit">Create account</button>
        </form>
    </section>
</main>
</body>
</html>
