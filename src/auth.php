<?php
declare(strict_types=1);

function current_user(): ?array
{
    $userId = $_SESSION['user_id'] ?? null;
    if (!is_int($userId) || $userId < 1) {
        return null;
    }

    $statement = db()->prepare(
        'SELECT id, name, email, role, last_login_at FROM users WHERE id = :id LIMIT 1'
    );
    $statement->execute(['id' => $userId]);
    $user = $statement->fetch();

    if ($user === false) {
        unset(
            $_SESSION['user_id'],
            $_SESSION['user_role'],
            $_SESSION['user_name'],
            $_SESSION['user_email'],
            $_SESSION['last_activity_at']
        );
        return null;
    }

    if (!is_string($user['role']) || $user['role'] === '') {
        throw new UnexpectedValueException('The user account has no valid role.');
    }

    $_SESSION['user_role'] = $user['role'];
    return $user;
}

function require_login(): array
{
    $user = current_user();
    if ($user !== null) {
        return $user;
    }

    if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'GET') {
        $intendedUrl = intended_url_from_request();
        if ($intendedUrl !== null) {
            $_SESSION['_intended_url'] = $intendedUrl;
        }
    }

    redirect('login.php');
}

function require_guest(): void
{
    if (current_user() !== null) {
        redirect('dashboard.php');
    }
}

function require_role(string $role): array
{
    $user = require_login();
    if (($user['role'] ?? null) !== $role) {
        render_forbidden_page();
    }

    return $user;
}

function login_throttle_status(string $email, string $ipAddress): array
{
    $cutoff = date('Y-m-d H:i:s', time() - 900);
    $pdo = db();
    $status = ['blocked' => false, 'minutes' => 0];

    foreach ([
        ['column' => 'email', 'value' => $email],
        ['column' => 'ip_address', 'value' => $ipAddress],
    ] as $identifier) {
        $statement = $pdo->prepare(
            "SELECT COUNT(*) AS failures, MIN(attempted_at) AS oldest_attempt "
            . "FROM login_attempts WHERE {$identifier['column']} = :value AND attempted_at >= :cutoff"
        );
        $statement->execute([
            'value' => $identifier['value'],
            'cutoff' => $cutoff,
        ]);
        $attempts = $statement->fetch();

        if ($attempts !== false && (int) $attempts['failures'] >= 5) {
            $oldestAttempt = strtotime((string) $attempts['oldest_attempt']);
            if ($oldestAttempt === false) {
                throw new UnexpectedValueException('A login attempt has an invalid timestamp.');
            }

            $minutes = max(1, (int) ceil(($oldestAttempt + 900 - time()) / 60));
            $status['blocked'] = true;
            $status['minutes'] = max($status['minutes'], $minutes);
        }
    }

    return $status;
}

function record_login_failure(string $email, string $ipAddress): array
{
    $statement = db()->prepare(
        'INSERT INTO login_attempts (email, ip_address, attempted_at) VALUES (:email, :ip_address, :attempted_at)'
    );
    $statement->execute([
        'email' => $email,
        'ip_address' => $ipAddress,
        'attempted_at' => date('Y-m-d H:i:s'),
    ]);

    return login_throttle_status($email, $ipAddress);
}

function clear_login_attempts(string $email, string $ipAddress): void
{
    $statement = db()->prepare(
        'DELETE FROM login_attempts WHERE email = :email OR ip_address = :ip_address'
    );
    $statement->execute([
        'email' => $email,
        'ip_address' => $ipAddress,
    ]);
}

function auth_navbar(array $user): void
{
    $baseUrl = auth_base_url();
    echo '<nav class="site-nav" aria-label="Main navigation"><a href="' . e($baseUrl) . 'dashboard.php">Dashboard</a>';
    echo '<a href="' . e($baseUrl) . 'profile.php">Profile</a>';
    if (($user['role'] ?? null) === 'admin') {
        echo '<a href="' . e($baseUrl) . 'admin/users.php">Admin</a>';
    }
    echo '</nav>';
}

function auth_base_url(): string
{
    $appRoot = realpath(dirname(__DIR__));
    $documentRoot = isset($_SERVER['DOCUMENT_ROOT']) && is_string($_SERVER['DOCUMENT_ROOT'])
        ? realpath($_SERVER['DOCUMENT_ROOT'])
        : false;

    if ($appRoot !== false && $documentRoot !== false) {
        $normalizedAppRoot = rtrim(str_replace('\\', '/', $appRoot), '/');
        $normalizedDocumentRoot = rtrim(str_replace('\\', '/', $documentRoot), '/');
        $documentRootLength = strlen($normalizedDocumentRoot);
        $appIsInDocumentRoot = strncasecmp($normalizedAppRoot, $normalizedDocumentRoot, $documentRootLength) === 0
            && (
                strlen($normalizedAppRoot) === $documentRootLength
                || substr($normalizedAppRoot, $documentRootLength, 1) === '/'
            );

        if ($appIsInDocumentRoot) {
            $relativeAppRoot = trim(substr($normalizedAppRoot, $documentRootLength), '/');
            return $relativeAppRoot === '' ? '/' : '/' . $relativeAppRoot . '/';
        }
    }

    $scriptName = $_SERVER['SCRIPT_NAME'] ?? '';
    if (is_string($scriptName)) {
        $scriptPath = str_replace('\\', '/', $scriptName);
        if (str_ends_with($scriptPath, '/admin/users.php')) {
            return substr($scriptPath, 0, -strlen('admin/users.php'));
        }
        return rtrim(str_replace('\\', '/', dirname($scriptPath)), '/') . '/';
    }

    return '/';
}

function render_forbidden_page(): void
{
    http_response_code(403);
    $user = current_user();
    $baseUrl = auth_base_url();
    ?>
    <!doctype html>
    <html lang="en">
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>Access denied</title>
        <link rel="stylesheet" href="<?= e($baseUrl) ?>assets/auth.css">
    </head>
    <body>
    <?php if ($user !== null): ?>
        <?php auth_navbar($user); ?>
    <?php endif; ?>
    <main class="auth-page">
        <section class="auth-card" aria-labelledby="page-title">
            <div class="auth-heading">
                <p class="eyebrow">Access denied</p>
                <h1 id="page-title">You can’t access this page</h1>
                <p class="muted">Your account does not have permission to view this area.</p>
            </div>
            <a class="button button-link" href="<?= e($baseUrl) ?>dashboard.php">Return to dashboard</a>
        </section>
    </main>
    </body>
    </html>
    <?php
    exit;
}

function intended_url_from_request(): ?string
{
    $requestUri = $_SERVER['REQUEST_URI'] ?? null;
    $scriptName = $_SERVER['SCRIPT_NAME'] ?? null;
    if (!is_string($requestUri) || !is_string($scriptName)) {
        return null;
    }

    $request = parse_url($requestUri);
    $script = parse_url($scriptName);
    if ($request === false || $script === false || !isset($request['path'], $script['path'])) {
        return null;
    }

    $appRoot = realpath(dirname(__DIR__));
    $documentRoot = isset($_SERVER['DOCUMENT_ROOT']) && is_string($_SERVER['DOCUMENT_ROOT'])
        ? realpath($_SERVER['DOCUMENT_ROOT'])
        : false;
    $basePath = null;

    if ($appRoot !== false && $documentRoot !== false) {
        $normalizedAppRoot = rtrim(str_replace('\\', '/', $appRoot), '/');
        $normalizedDocumentRoot = rtrim(str_replace('\\', '/', $documentRoot), '/');
        $documentRootLength = strlen($normalizedDocumentRoot);
        $appIsInDocumentRoot = strncasecmp($normalizedAppRoot, $normalizedDocumentRoot, $documentRootLength) === 0
            && (
                strlen($normalizedAppRoot) === $documentRootLength
                || substr($normalizedAppRoot, $documentRootLength, 1) === '/'
            );

        if ($appIsInDocumentRoot) {
            $basePath = trim(substr($normalizedAppRoot, $documentRootLength), '/');
            $basePath = $basePath === '' ? '' : '/' . $basePath;
        }
    }

    if ($basePath === null) {
        $basePath = rtrim(str_replace('\\', '/', dirname($script['path'])), '/');
    }

    $requestPath = $request['path'];
    if ($basePath !== '' && !str_starts_with($requestPath, $basePath . '/')) {
        return null;
    }

    $relativePath = $basePath === '' ? ltrim($requestPath, '/') : substr($requestPath, strlen($basePath) + 1);
    $relativeUrl = $relativePath;
    if (isset($request['query'])) {
        $relativeUrl .= '?' . $request['query'];
    }

    return is_valid_relative_url($relativeUrl) ? $relativeUrl : null;
}

function is_valid_relative_url(string $url): bool
{
    if ($url === '' || preg_match('/[\x00-\x20\x7f\\\\]/', $url) === 1) {
        return false;
    }

    $parts = parse_url($url);
    if ($parts === false || isset($parts['scheme']) || isset($parts['host']) || isset($parts['user']) || isset($parts['pass'])) {
        return false;
    }

    $path = $parts['path'] ?? '';
    if (
        $path === ''
        || str_starts_with($path, '/')
        || preg_match('~\A[A-Za-z0-9._/-]+\z~', $path) !== 1
        || isset($parts['fragment'])
    ) {
        return false;
    }

    foreach (explode('/', $path) as $segment) {
        if ($segment === '.' || $segment === '..') {
            return false;
        }
    }

    return true;
}

function take_intended_url(): ?string
{
    $intendedUrl = $_SESSION['_intended_url'] ?? null;
    unset($_SESSION['_intended_url']);

    return is_string($intendedUrl) && is_valid_relative_url($intendedUrl)
        ? $intendedUrl
        : null;
}
