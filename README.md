# SWD PHP Authentication

A PHP 8 authentication example for XAMPP and the MySQL `swd_auth` database.

## Setup

1. Create the `swd_auth` database and configure the connection in `config/database.php`, or set `SWD_AUTH_DSN`, `SWD_AUTH_DB_USER`, and `SWD_AUTH_DB_PASSWORD` in the PHP process environment.
2. Ensure `users` has the columns used by the application: `id`, `name`, `email`, `password_hash`, `role`, `created_at`, and `last_login_at`. Make `email` unique.
3. Ensure `login_attempts` has `id`, `email`, `ip_address`, and `attempted_at` columns. Index `(email, attempted_at)` and `(ip_address, attempted_at)` for efficient throttling.
4. Visit `register.php` to create an account. New registrations receive the `user` role.
5. Promote the first administrator from a terminal:

   ```text
   C:\xampp\php\php.exe C:\xampp\htdocs\swd\06-php-auth\promote-admin.php me@example.com
   ```

The promotion script is CLI-only. Configure its database connection using the same PHP environment as the web server.

## Security features

- Passwords are stored with PHP's `password_hash()` and checked with `password_verify()`. Passwords are never stored as plaintext or fast hashes such as MD5 or SHA-1. Password hashes are upgraded on successful login when PHP indicates that rehashing is needed.
- Registration and password changes require at least 10 characters, a letter, and a number. Password changes also verify the current password.
- PDO uses prepared statements and exception-mode error handling for database operations.
- Authentication forms use CSRF tokens. Logout accepts POST only and destroys the session and cookie.
- Sessions use a dedicated name, strict mode, cookie-only transport, HttpOnly, SameSite=Lax, and Secure cookies when HTTPS is active. Session IDs are rotated after login, registration, and password changes. Inactivity expires authenticated sessions after 30 minutes.
- Login failures are tracked by email and client IP. Five failures in the last 15 minutes block another attempt until the oldest failure ages out. A successful login clears matching attempts.
- Protected pages check authorization on the server. Admin role changes require CSRF verification; an administrator cannot demote their own account.
- Intended post-login destinations are constrained to validated, relative application paths to prevent external redirects.
- Dynamic HTML output is escaped. Responses include `X-Frame-Options`, `X-Content-Type-Options`, and `Referrer-Policy` headers.
- `config/.htaccess` denies direct web access to the database configuration directory on Apache.

## Deployment notes

`bootstrap.php` enables PHP error display for local development. Disable `display_errors` and `display_startup_errors` in production and log errors privately instead. Serve the application over HTTPS in production so session cookies receive the Secure flag. Keep database credentials out of source control and use a least-privilege database account.

The application expects the column names above. Adjust its prepared SQL statements if an existing schema uses different names.
