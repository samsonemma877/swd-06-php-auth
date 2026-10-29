<?php
declare(strict_types=1);

require_once dirname(__DIR__) . '/bootstrap.php';

$admin = require_role('admin');
$errors = [];

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $userIdInput = $_POST['user_id'] ?? '';
    $roleInput = $_POST['role'] ?? '';

    if (!csrf_verify()) {
        http_response_code(403);
        $errors[] = 'Your form session expired or could not be verified. Please refresh the page and try again.';
    } elseif (
        !is_string($userIdInput)
        || preg_match('/\A[1-9][0-9]*\z/', $userIdInput) !== 1
        || !is_string($roleInput)
        || !in_array($roleInput, ['admin', 'user'], true)
    ) {
        http_response_code(400);
        $errors[] = 'The requested user or role is invalid.';
    } elseif ((int) $userIdInput === (int) $admin['id'] && $roleInput !== 'admin') {
        http_response_code(400);
        $errors[] = 'You cannot remove your own admin role.';
    } else {
        $update = db()->prepare('UPDATE users SET role = :role WHERE id = :id');
        $update->execute([
            'role' => $roleInput,
            'id' => (int) $userIdInput,
        ]);

        if ($update->rowCount() === 0) {
            $checkUser = db()->prepare('SELECT id FROM users WHERE id = :id LIMIT 1');
            $checkUser->execute(['id' => (int) $userIdInput]);
            if ($checkUser->fetch() === false) {
                http_response_code(404);
                $errors[] = 'That user could not be found.';
            } else {
                flash('success', 'The user role is unchanged.');
                redirect('admin/users.php');
            }
        } else {
            flash('success', 'The user role has been updated.');
            redirect('admin/users.php');
        }
    }
}

$users = db()->query(
    'SELECT id, name, email, role, created_at, last_login_at FROM users ORDER BY id ASC'
)->fetchAll();
$successMessage = flash('success');
?>
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Manage users</title>
    <link rel="stylesheet" href="../assets/auth.css">
</head>
<body>
<?php auth_navbar($admin); ?>
<main class="auth-page auth-page-wide">
    <section class="auth-card auth-card-wide" aria-labelledby="page-title">
        <div class="auth-heading">
            <p class="eyebrow">Administration</p>
            <h1 id="page-title">Manage users</h1>
            <p class="muted">Review accounts and assign user or admin roles.</p>
        </div>

        <?php if ($successMessage !== null): ?>
            <div class="notice notice-success" role="status"><?= e($successMessage) ?></div>
        <?php endif; ?>

        <?php if ($errors !== []): ?>
            <div class="notice notice-error" role="alert">
                <ul>
                    <?php foreach ($errors as $error): ?>
                        <li><?= e($error) ?></li>
                    <?php endforeach; ?>
                </ul>
            </div>
        <?php endif; ?>

        <div class="table-wrap">
            <table class="user-table">
                <thead>
                <tr>
                    <th scope="col">Name</th>
                    <th scope="col">Email</th>
                    <th scope="col">Role</th>
                    <th scope="col">Created</th>
                    <th scope="col">Last login</th>
                    <th scope="col">Change role</th>
                </tr>
                </thead>
                <tbody>
                <?php foreach ($users as $user): ?>
                    <tr>
                        <td><?= e($user['name']) ?></td>
                        <td><?= e($user['email']) ?></td>
                        <td><?= e($user['role']) ?></td>
                        <td><?= e($user['created_at'] ?? 'Not recorded') ?></td>
                        <td><?= e($user['last_login_at'] ?? 'Never') ?></td>
                        <td>
                            <?php if ((int) $user['id'] === (int) $admin['id']): ?>
                                <span class="muted">You cannot change your own role.</span>
                            <?php else: ?>
                                <form class="role-form" method="post" action="users.php">
                                    <?= csrf_field() ?>
                                    <input type="hidden" name="user_id" value="<?= e($user['id']) ?>">
                                    <label class="visually-hidden" for="role-<?= e($user['id']) ?>">Role for <?= e($user['name']) ?></label>
                                    <select id="role-<?= e($user['id']) ?>" name="role">
                                        <option value="user"<?= $user['role'] === 'user' ? ' selected' : '' ?>>User</option>
                                        <option value="admin"<?= $user['role'] === 'admin' ? ' selected' : '' ?>>Admin</option>
                                    </select>
                                    <button class="button button-small" type="submit">Save</button>
                                </form>
                            <?php endif; ?>
                        </td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        </div>
    </section>
</main>
</body>
</html>
