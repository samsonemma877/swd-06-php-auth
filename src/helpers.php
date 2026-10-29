<?php
declare(strict_types=1);

function e(string|int|float|null $value): string
{
    return htmlspecialchars((string) $value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function redirect(string $location): void
{
    header('Location: ' . $location, true, 303);
    exit;
}

function flash(string $key, ?string $message = null): ?string
{
    if ($message !== null) {
        $_SESSION['_flash'][$key] = $message;
        return null;
    }

    $value = $_SESSION['_flash'][$key] ?? null;
    unset($_SESSION['_flash'][$key]);

    return is_string($value) ? $value : null;
}

function old(string $key, string $default = ''): string
{
    $value = $_SESSION['_old'][$key] ?? $default;

    return is_string($value) ? $value : $default;
}
