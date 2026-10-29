<?php
declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

if (!isset($_SESSION['user_id']) || !is_int($_SESSION['user_id'])) {
    redirect('register.php');
}

$userName = $_SESSION['user_name'] ?? '';
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
<main class="auth-page">
    <section class="auth-card" aria-labelledby="page-title">
        <?php if ($successMessage !== null): ?>
            <div class="notice notice-success" role="status"><?= e($successMessage) ?></div>
        <?php endif; ?>
        <div class="auth-heading">
            <p class="eyebrow">Account</p>
            <h1 id="page-title">Welcome, <?= e(is_string($userName) ? $userName : '') ?></h1>
            <p class="muted">You are signed in.</p>
        </div>
    </section>
</main>
</body>
</html>
