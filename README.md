# PHP Patch Check

A single PHP file that checks whether a website is running a PHP version patched against **CVE-2026-109618** and **CVE-2026-109619**. Both are critical (CVSS v4.0 9.2) and allow unauthenticated remote code execution.

It works without root access, so customers on shared hosting can run it themselves. It shows the result in the browser or on the command line.

## What it checks

| Check | How |
| --- | --- |
| PHP 8.2, 8.3, 8.4, 8.5 | Compares the version with the fixed upstream release: 8.2.35, 8.3.36, 8.4.27, 8.5.12 |
| Older PHP (7.4, 8.1) and CloudLinux alt-php | Reads the PHP build date. These get the fix as a backport, so the version number does not change |
| PHP type | Detects cPanel ea-php (MultiPHP) or CloudLinux alt-php (PHP Selector) from the PHP install paths |
| Interim mitigation | Shows whether `session.upload_progress.enabled` is on or off |

### Results

| Result | Meaning |
| --- | --- |
| **PATCHED** | The version is at or above the fixed upstream release |
| **LIKELY PATCHED** | The version number is unchanged, but PHP was built on or after `PATCH_DATE`, which matches a backported fix |
| **NOT PATCHED** | PHP was built before the fix. Contact your hosting provider |
| **UNKNOWN** | The build date could not be read, usually because `phpinfo` is disabled. Ask your hosting provider |

### Upgrade recommendation

Below the result, the script adds a recommendation when the site runs an old PHP branch:

- **PHP 8.1 or older:** end of life with no official security updates. It recommends switching to PHP 8.3 or 8.4 through Select PHP Version or MultiPHP Manager, after taking a backup.
- **PHP 8.2:** security updates end on 31 Dec 2026. It recommends planning a move to 8.3 or 8.4.
- **PHP 8.3 and later:** no recommendation is shown.

## Requirements

- PHP 5.5 or later, so it also runs on old CloudLinux alt-php versions such as 5.6, 7.x and 8.0
- `phpinfo` not listed in `disable_functions` (needed only for the build-date check)

PHP 7.4, 8.0 and 8.1 are end of life upstream, so they never reach a "fixed" version number. For these, and for every alt-php version, the script judges by build date. For example, a CloudLinux site on alt-php 8.0.30 built on or after 20 Oct 2026 shows **LIKELY PATCHED**.

## Run it in a browser (no root access needed)

1. Log in to cPanel and open **File Manager**.
2. Go to the website's folder, usually `public_html`.
3. Upload `check-php-patch.php` and **rename it to something hard to guess**, for example `check-8f3k2.php`.
4. Open `https://yourdomain.com/check-8f3k2.php` in your browser.
5. Read the result at the top of the page.
6. **Delete the file straight away.**

If the account has several domains on different PHP versions, repeat the check in each domain's folder. The browser check is the most reliable one, because it tests the PHP your website actually uses.


## Run it as root on every installed PHP version (for VPS and Dedicated Server customers only)

Server administrators can check every installed ea-php and alt-php version in one go:

```bash
for p in /opt/cpanel/ea-php*/root/usr/bin/php /opt/alt/php[0-9]*/usr/bin/php; do
  [ -x "$p" ] && echo "== $p" && "$p" check-php-patch.php | head -2
done
```

For a definitive answer, check the package changelog for the CVE IDs. For CloudLinux alt-php, use the same check on the alt-php package, for example `rpm -q --changelog alt-php80-common | head -20`. For ea-php:

```bash
for v in 74 81 82 83 84 85; do
  rpm -q ea-php$v-php-common >/dev/null 2>&1 || continue
  echo "== ea-php$v"
  rpm -q --changelog ea-php$v-php-common | grep -m3 -E '109618|109619' || echo "  no CVE mention - check for update"
done
```

## Configuration

Edit the values at the top of the file.

| Setting | Default | Purpose |
| --- | --- | --- |
| `PATCH_DATE` | `2026-10-20` | Earliest build date of the patched packages. cPanel built its patched ea-php on 20 Oct 2026. Adjust if your patched builds are dated differently |
| `$fixed` | 8.2.35 to 8.5.12 | Fixed upstream release for each PHP branch |
| `AUTHOR_NAME`, `AUTHOR_URL` | LankaHost | Shown in the page footer |

## Security notes

- **Delete the file after use.** Do not leave it on a live website.
- Use a hard-to-guess filename while it is uploaded.
- The page shows only the values needed for this check, never the full `phpinfo` output. It also sends `noindex` and `no-store` headers.

## Limitations

- A build date shows when PHP was compiled, not which fixes went in. That is why backported builds show **LIKELY PATCHED**. The `rpm --changelog` check above is the definitive test.
- The result reflects the PHP files on disk. If PHP was not restarted after the update, running processes may still use the old code. Restart Apache and PHP-FPM after updating.
- Upload progress being **Off** reduces risk, but it does not replace the update.

## Author

© 2026 LankaHost Web Solutions (Private) Limited
[www.lankahost.lk](https://www.lankahost.lk)
