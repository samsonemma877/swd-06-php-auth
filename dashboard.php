<?php
declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

$user = require_login();
$successMessage = flash('success');
?>
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Dashboard</title>
    <link rel="stylesheet" href="assets/auth.css">
</head>
<body>
<?php auth_navbar($user); ?>
<main class="auth-page">
    <section class="auth-card" aria-labelledby="page-title">
        <?php if ($successMessage !== null): ?>
            <div class="notice notice-success" role="status"><?= e($successMessage) ?></div>
        <?php endif; ?>
        <div class="auth-heading">
            <p class="eyebrow">Account</p>
            <h1 id="page-title">Welcome, <?= e($user['name']) ?></h1>
            <p class="muted">You are signed in.</p>
        </div>
        <dl class="account-details">
            <div><dt>Name</dt><dd><?= e($user['name']) ?></dd></div>
            <div><dt>Email</dt><dd><?= e($user['email']) ?></dd></div>
            <div><dt>Role</dt><dd><?= e($user['role']) ?></dd></div>
            <div><dt>Last login</dt><dd><?= e($user['last_login_at'] ?? 'Not recorded') ?></dd></div>
        </dl>
        <form method="post" action="logout.php">
            <?= csrf_field() ?>
            <button class="button button-secondary" type="submit">Sign out</button>
        </form>
    </section>
</main>
</body>
</html>
