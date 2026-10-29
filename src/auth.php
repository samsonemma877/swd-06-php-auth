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
        http_response_code(403);
        exit('You do not have permission to access this page.');
    }

    return $user;
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
