# PHP Patch Check

A single PHP file that checks whether a website is running a PHP version patched against **CVE-2026-109618** and **CVE-2026-109619** ("PHP2Shell"). Both are critical (CVSS v4.0 9.2) and allow unauthenticated remote code execution.

It works without root access, so customers on shared hosting can run it themselves. It shows the result in the browser or on the command line.

The fixed build list and verification method follow CloudLinux's article [PHP CVE-2026-109618 / CVE-2026-109619 (PHP2Shell): fixed alt-php and ea-php packages and how to verify](https://cloudlinux.zendesk.com/hc/en-us/articles/31194180517916-PHP-CVE-2026-109618-CVE-2026-109619-PHP2Shell-fixed-alt-php-and-ea-php-packages-and-how-to-verify).

## What it checks

The script uses the most reliable check available, in this order:

| Order | Check | How |
| --- | --- | --- |
| 1 | Package changelog | Counts CVE-2026-109618 / 109619 entries in the `alt-phpNN-common` or `ea-phpNN-php-cli` changelog, CloudLinux's primary method. Needs `rpm` and `shell_exec`, so normally only works when run as root |
| 2 | Upstream version | PHP 8.2 to 8.5 at or above 8.2.35, 8.3.36, 8.4.27 or 8.5.12 |
| 3 | CloudLinux alt-php build list | Compares with CloudLinux's fixed builds (table below). An older PHP version is not patched. The same version is judged by its build date, because the fix is in the package release, not the version number |
| 4 | Build date | Other backported builds, such as older ea-php, built on or after `PATCH_DATE` |
| Always | Running code | Reads `/proc/self/maps`. If PHP files replaced by the update are still loaded in memory, the result becomes **RESTART NEEDED** |

It also shows the PHP type (cPanel ea-php or CloudLinux alt-php) and whether `session.upload_progress.enabled` is on.

### CloudLinux alt-php fixed builds (CloudLinux OS 7, 8 and 9)

| alt-php | Fixed build | alt-php | Fixed build |
| --- | --- | --- | --- |
| 52 | 5.2.17-242 | 73 | 7.3.33-82 |
| 53 | 5.3.29-220 | 74 | 7.4.33-81 |
| 54 | 5.4.45-203 | 80 | 8.0.30-69 |
| 55 | 5.5.38-183 | 81 | 8.1.34-39 |
| 56 | 5.6.40-147 | 82 | 8.2.34-7 |
| 70 | 7.0.33-148 | 83 | 8.3.35-6 |
| 71 | 7.1.33-114 | 84 | 8.4.26-5 |
| 72 | 7.2.34-97 | 85 | 8.5.11-5 |

alt-php44 and alt-php51 have no fixed build.

### Results

| Result | Meaning |
| --- | --- |
| **PATCHED** | Confirmed by the package changelog, the upstream version, or a version newer than CloudLinux's fixed build |
| **LIKELY PATCHED** | Same version as the fixed build, and PHP was built on or after `PATCH_DATE`. Confirm the exact build with `rpm` as root |
| **RESTART NEEDED** | PHP was updated on disk, but this PHP process still runs the old code. Restart PHP |
| **NOT PATCHED** | Older than the fixed build, built before the fix, or the changelog does not list it. Update PHP |
| **NO FIX AVAILABLE** | alt-php 4.4 or 5.1. Move the site to a supported version |
| **UNKNOWN** | The build date could not be read, usually because `phpinfo` is disabled |

### Upgrade recommendation

Below the result, the script adds a recommendation when the site runs an old PHP branch:

- **PHP 8.1 or older:** end of life with no official security updates. It recommends switching to PHP 8.3 or 8.4 through Select PHP Version or MultiPHP Manager, after taking a backup.
- **PHP 8.2:** security updates end on 31 Dec 2026. It recommends planning a move to 8.3 or 8.4.
- **PHP 8.3 and later:** no recommendation is shown.

## Requirements

- PHP 5.5 or later, so it also runs on old CloudLinux alt-php versions such as 5.6, 7.x and 8.0
- `phpinfo` not listed in `disable_functions` (needed for the build-date check)
- Optional: `shell_exec` and `rpm` for the definitive changelog check

## Run it in a browser (no root access needed)

1. Log in to cPanel and open **File Manager**.
2. Go to the website's folder, usually `public_html`.
3. Upload `check-php-patch.php` and **rename it to something hard to guess**, for example `check-8f3k2.php`.
4. Open `https://yourdomain.com/check-8f3k2.php` in your browser.
5. Read the result at the top of the page.
6. **Delete the file straight away.**

If the account has several domains on different PHP versions, repeat the check in each domain's folder. The browser check tests the PHP your website actually uses.

## Run it from cPanel Terminal or SSH

```bash
php check-php-patch.php
```

On the command line, the PHP version can differ from the one your website uses. Use the browser check to confirm what the site runs.

## Run it as root on every installed PHP version

As root, the script can read package changelogs, so results are definitive:

```bash
for p in /opt/cpanel/ea-php*/root/usr/bin/php /opt/alt/php[0-9]*/usr/bin/php; do
  [ -x "$p" ] && echo "== $p" && "$p" check-php-patch.php | head -2
done
```

CloudLinux's own check, without the script. Each package should print 1 or more:

```bash
for p in $(rpm -qa 'ea-php*-php-cli' 'alt-php*-common' --qf '%{NAME}\n'); do
  echo "$p $(rpm -q --changelog $p | grep -cE 'CVE-2026-(109618|109619)')"
done
```

## After updating: restart PHP

The fix is not active until PHP processes restart. No reboot is needed.

```bash
# cPanel with Apache
/scripts/restartsrv_httpd
/scripts/restartsrv_apache_php_fpm

# LiteSpeed: a web server restart does not always stop running lsphp processes
/usr/local/lsws/bin/lswsctrl restart
pkill lsphp
```

To confirm Apache restarted after the update, its start time should be later than the newest package install:

```bash
systemctl show httpd -p ActiveEnterTimestamp
rpm -qa 'alt-php*' 'ea-php*' --last | head -1
```

## Interim mitigation

Until every version is patched, turn off upload progress for all alt-php versions. This reduces risk but does not replace the update.

```bash
# In /etc/cl.selector/global_php.ini set:
#   session.upload_progress.enabled = Off
cagefsctl --setup-cl-selector
```

Keep the Imunify360 WAF enabled with ruleset 8.84 or later.

## Configuration

Edit the values at the top of the file.

| Setting | Default | Purpose |
| --- | --- | --- |
| `PATCH_DATE` | `2026-10-20` | Earliest build date of patched packages. cPanel built patched ea-php on 20 Oct 2026 and CloudLinux alt-php on 21 Oct 2026 |
| `$fixedUpstream` | 8.2.35 to 8.5.12 | Fixed upstream release for each PHP branch |
| `$altFixed` | CloudLinux list | Fixed alt-php build for each version |
| `$altNoFix` | 44, 51 | alt-php versions with no fixed build |
| `AUTHOR_NAME`, `AUTHOR_URL` | LankaHost | Shown in the page footer |

## Security notes

- **Delete the file after use.** Do not leave it on a live website.
- Use a hard-to-guess filename while it is uploaded.
- The page shows only the values needed for this check, never the full `phpinfo` output. It also sends `noindex` and `no-store` headers.
- The only shell commands are read-only `rpm -q` queries with fixed package names.

## Limitations

- Without root, the script cannot see the package release, so a same-version alt-php build shows **LIKELY PATCHED** rather than **PATCHED**. The `rpm` checks above are definitive.
- **RESTART NEEDED** checks only the PHP process that ran the script. Other long-running workers may still hold old code, so always restart PHP after updating.
- The restart check needs `/proc/self/maps`. If `open_basedir` blocks it, Running code shows "Could not check".
- Upload progress being **Off** reduces risk, but it does not replace the update.

## Author

© 2026 LankaHost Web Solutions (Private) Limited
[www.lankahost.lk](https://www.lankahost.lk)
