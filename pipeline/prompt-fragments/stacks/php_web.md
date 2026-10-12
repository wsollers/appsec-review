---
id: php_web
version: 1
covers: []
standards: ["cwe", "asvs5"]
max_tokens: 1500
---
## Runtime and framework model
A PHP web application: Laravel, Symfony, WordPress (core, plugins, themes), Drupal, Magento,
CodeIgniter, or plain PHP scripts behind PHP-FPM or `mod_php`. Each request starts fresh; any
`.php` file reachable under the document root is an entry point unless the front controller and
server configuration prevent it. Loose comparisons and type juggling shape many bugs.

## Trust and interface layer
- Entry points: routes and controllers, directly requested `.php` files, WordPress
  `admin-ajax.php` actions (`wp_ajax_` and `wp_ajax_nopriv_`), REST routes, shortcodes,
  `admin-post.php` handlers, cron hooks, and CLI commands.
- Superglobals (`$_GET`, `$_POST`, `$_COOKIE`, `$_FILES`, `$_SERVER['HTTP_*']`) are raw input;
  `$_REQUEST` merges them.
- Laravel middleware groups and Symfony firewalls/access_control govern authentication;
  WordPress relies on `current_user_can` and nonces inside each handler.

## Idiomatic security mechanisms
- PDO prepared queries with bound parameters (`ATTR_EMULATE_PREPARES` false), Eloquent and
  Doctrine query builders, `$wpdb->prepare`.
- Blade `{{ }}` and Twig autoescape; `esc_html`, `esc_attr`, `esc_url`, `wp_kses` in WordPress.
- CSRF middleware (Laravel `VerifyCsrfToken`), Symfony CSRF tokens, `check_admin_referer`/
  `wp_verify_nonce` plus capability checks.
- `password_hash`/`password_verify`, `random_bytes`, `hash_equals`.
- `escapeshellarg` per argument when a shell cannot be avoided.

## Stack-specific pitfalls
- `unserialize` on cookies, form fields, or cache values (POP chains in framework and plugin
  classes); `phar://` wrappers triggering deserialization through file functions.
- `include`/`require` with user input (local or remote file inclusion), `allow_url_include`.
- Loose comparison: `==` between a hash and `"0e..."`, `in_array` without strict mode,
  `strcmp` with array input returning null.
- `extract($_POST)`, mass assignment through `$fillable`/`$guarded = []` in Eloquent.
- `{!! $var !!}` in Blade, `|raw` in Twig, `echo $_GET[...]`.
- WordPress `wp_ajax_nopriv_` handlers performing privileged actions; nonces used as
  authorization without `current_user_can`.
- Uploads stored in the web root with `.php`, `.phtml`, or `.htaccess` names.
- `preg_replace` with `/e` (old PHP), `assert` with strings, `create_function`.
- `file_get_contents`, `curl` or `fopen` on user URLs with wrappers (`php://`, `data://`,
  `expect://`) and SSRF to internal hosts.

## Build and deployment facts to check
- PHP version and `php.ini` settings: `display_errors`, `allow_url_include`, `open_basedir`,
  `disable_functions`, session cookie flags.
- Web server rules for the document root, upload directories, and `.env` exposure.
- `composer.lock` presence and resolved versions; WordPress plugin and theme versions.
- `APP_DEBUG`/`APP_ENV` in Laravel, Symfony `APP_ENV` and profiler exposure.
