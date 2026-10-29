<?php
declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

$user = require_login();
$profileErrors = [];
$passwordErrors = [];
$profileName = (string) $user['name'];
$profileEmail = (string) $user['email'];

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $formInput = $_POST['form'] ?? '';

    if (!csrf_verify()) {
        http_response_code(403);
        $profileErrors[] = 'Your form session expired or could not be verified. Please refresh the page and try again.';
    } elseif ($formInput === 'profile') {
        $nameInput = $_POST['name'] ?? '';
        $emailInput = $_POST['email'] ?? '';
        $profileName = is_string($nameInput) ? trim($nameInput) : '';
        $profileEmail = is_string($emailInput) ? strtolower(trim($emailInput)) : '';

        if ($profileName === '') {
            $profileErrors[] = 'Please enter your name.';
        } elseif (strlen($profileName) > 100) {
            $profileErrors[] = 'Name must be 100 characters or fewer.';
        }

        if (filter_var($profileEmail, FILTER_VALIDATE_EMAIL) === false || strlen($profileEmail) > 254) {
            $profileErrors[] = 'Enter a valid email address (maximum 254 characters).';
        }

        if ($profileErrors === []) {
            $pdo = db();
            $emailCheck = $pdo->prepare('SELECT id FROM users WHERE email = :email AND id <> :id LIMIT 1');
            $emailCheck->execute([
                'email' => $profileEmail,
                'id' => $user['id'],
            ]);

            if ($emailCheck->fetch() !== false) {
                $profileErrors[] = 'An account with that email address already exists.';
            } else {
                $update = $pdo->prepare('UPDATE users SET name = :name, email = :email WHERE id = :id');

                try {
                    $update->execute([
                        'name' => $profileName,
                        'email' => $profileEmail,
                        'id' => $user['id'],
                    ]);
                } catch (PDOException $exception) {
                    if ($exception->getCode() !== '23000') {
                        throw $exception;
                    }

                    $emailCheck->execute([
                        'email' => $profileEmail,
                        'id' => $user['id'],
                    ]);
                    if ($emailCheck->fetch() === false) {
                        throw $exception;
                    }

                    $profileErrors[] = 'An account with that email address already exists.';
                }

                if ($profileErrors === []) {
                    $_SESSION['user_name'] = $profileName;
                    $_SESSION['user_email'] = $profileEmail;
                    flash('success', 'Your profile has been updated.');
                    redirect('profile.php');
                }
            }
        }
    } elseif ($formInput === 'password') {
        $currentPasswordInput = $_POST['current_password'] ?? '';
        $newPasswordInput = $_POST['new_password'] ?? '';
        $confirmPasswordInput = $_POST['confirm_password'] ?? '';
        $currentPassword = is_string($currentPasswordInput) ? $currentPasswordInput : '';
        $newPassword = is_string($newPasswordInput) ? $newPasswordInput : '';
        $confirmPassword = is_string($confirmPasswordInput) ? $confirmPasswordInput : '';

        $passwordStatement = db()->prepare('SELECT password_hash FROM users WHERE id = :id LIMIT 1');
        $passwordStatement->execute(['id' => $user['id']]);
        $passwordHash = $passwordStatement->fetchColumn();

        if (!is_string($passwordHash) || !password_verify($currentPassword, $passwordHash)) {
            $passwordErrors[] = 'The current password is incorrect.';
        }

        $passwordLength = preg_match_all('/./us', $newPassword, $passwordCharacters);
        if ($passwordLength === false || $passwordLength < 10) {
            $passwordErrors[] = 'New password must be at least 10 characters long.';
        }
        if (preg_match('/\p{L}/u', $newPassword) !== 1 || preg_match('/[0-9]/', $newPassword) !== 1) {
            $passwordErrors[] = 'New password must contain at least one letter and one number.';
        }
        if ($newPassword !== $confirmPassword) {
            $passwordErrors[] = 'New passwords do not match.';
        }

        if ($passwordErrors === []) {
            $newPasswordHash = password_hash($newPassword, PASSWORD_DEFAULT);
            if (!is_string($newPasswordHash)) {
                throw new RuntimeException('Unable to securely hash the new password.');
            }

            $update = db()->prepare(
                'UPDATE users SET password_hash = :password_hash, auth_version = auth_version + 1 WHERE id = :id'
            );
            $update->execute([
                'password_hash' => $newPasswordHash,
                'id' => $user['id'],
            ]);

            if ($update->rowCount() !== 1) {
                throw new RuntimeException('Unable to update the password and revoke existing sessions.');
            }

            $versionStatement = db()->prepare('SELECT auth_version FROM users WHERE id = :id LIMIT 1');
            $versionStatement->execute(['id' => $user['id']]);
            $updatedAuthVersion = $versionStatement->fetchColumn();
            if ($updatedAuthVersion === false) {
                throw new RuntimeException('Unable to load the updated authentication version.');
            }

            if (!session_regenerate_id(true)) {
                throw new RuntimeException('Unable to rotate the session identifier after changing the password.');
            }
            $_SESSION['auth_version'] = auth_version_value($updatedAuthVersion);
            unset($_SESSION['_csrf_token']);
            $_SESSION['last_activity_at'] = time();
            flash('success', 'Your password has been changed.');
            redirect('profile.php');
        }
    } else {
        http_response_code(400);
        $profileErrors[] = 'The submitted form is invalid.';
    }
}

$user = current_user();
if ($user === null) {
    redirect('login.php');
}
$successMessage = flash('success');
?>
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Profile</title>
    <link rel="stylesheet" href="assets/auth.css">
</head>
<body>
<?php auth_navbar($user); ?>
<main class="auth-page auth-page-wide">
    <div class="profile-sections">
        <section class="auth-card" aria-labelledby="profile-title">
            <div class="auth-heading">
                <p class="eyebrow">Account</p>
                <h1 id="profile-title">Profile details</h1>
                <p class="muted">Update your name and email address.</p>
            </div>

            <?php if ($successMessage !== null): ?>
                <div class="notice notice-success" role="status"><?= e($successMessage) ?></div>
            <?php endif; ?>

            <?php if ($profileErrors !== []): ?>
                <div class="notice notice-error" role="alert">
                    <ul>
                        <?php foreach ($profileErrors as $error): ?>
                            <li><?= e($error) ?></li>
                        <?php endforeach; ?>
                    </ul>
                </div>
            <?php endif; ?>

            <form method="post" action="profile.php">
                <?= csrf_field() ?>
                <input type="hidden" name="form" value="profile">
                <div class="form-field">
                    <label for="name">Name</label>
                    <input id="name" name="name" type="text" autocomplete="name" maxlength="100" required value="<?= e($profileName) ?>">
                </div>
                <div class="form-field">
                    <label for="email">Email address</label>
                    <input id="email" name="email" type="email" autocomplete="email" maxlength="254" required value="<?= e($profileEmail) ?>">
                </div>
                <button class="button" type="submit">Save profile</button>
            </form>
        </section>

        <section class="auth-card" aria-labelledby="password-title">
            <div class="auth-heading">
                <p class="eyebrow">Security</p>
                <h2 id="password-title">Change password</h2>
                <p class="muted">Confirm your current password before choosing a new one.</p>
            </div>

            <?php if ($passwordErrors !== []): ?>
                <div class="notice notice-error" role="alert">
                    <ul>
                        <?php foreach ($passwordErrors as $error): ?>
                            <li><?= e($error) ?></li>
                        <?php endforeach; ?>
                    </ul>
                </div>
            <?php endif; ?>

            <form method="post" action="profile.php">
                <?= csrf_field() ?>
                <input type="hidden" name="form" value="password">
                <div class="form-field">
                    <label for="current_password">Current password</label>
                    <input id="current_password" name="current_password" type="password" autocomplete="current-password" required>
                </div>
                <div class="form-field">
                    <label for="new_password">New password</label>
                    <input id="new_password" name="new_password" type="password" autocomplete="new-password" required>
                    <small>At least 10 characters, including a letter and a number.</small>
                </div>
                <div class="form-field">
                    <label for="confirm_password">Confirm new password</label>
                    <input id="confirm_password" name="confirm_password" type="password" autocomplete="new-password" required>
                </div>
                <button class="button" type="submit">Change password</button>
            </form>
        </section>
    </div>
</main>
</body>
</html>
