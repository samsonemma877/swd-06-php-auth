<?php
declare(strict_types=1);

define('DB_DSN', getenv('SWD_AUTH_DSN') ?: 'mysql:host=127.0.0.1;dbname=swd_auth;charset=utf8mb4');
define('DB_USER', getenv('SWD_AUTH_DB_USER') ?: 'root');
define('DB_PASSWORD', getenv('SWD_AUTH_DB_PASSWORD') ?: '');
