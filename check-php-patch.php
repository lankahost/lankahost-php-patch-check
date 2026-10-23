<?php
/**
 * PHP patch check for CVE-2026-109618 / CVE-2026-109619 ("PHP2Shell")
 *
 * Upload to the site's folder (e.g. public_html) under a hard-to-guess name,
 * open it in a browser, then DELETE IT. Shows only what is needed for the check.
 *
 * How it decides (most reliable first):
 *  1. Package changelog lists the CVE fix (needs rpm + shell_exec;
 *     usually only when run as root on the command line)           -> PATCHED
 *  2. PHP 8.2 / 8.3 / 8.4 / 8.5 at or above the fixed upstream release -> PATCHED
 *  3. CloudLinux alt-php: compared with CloudLinux's fixed build list.
 *     Older version -> NOT PATCHED. Same version -> judged by build date.
 *  4. Other backported builds (older ea-php): build date on or after
 *     PATCH_DATE                                                     -> LIKELY PATCHED
 *  Any result becomes RESTART NEEDED if this PHP process still runs
 *  code that was replaced on disk by the update.
 *
 * Fixed build list and verification method from CloudLinux:
 * https://cloudlinux.zendesk.com/hc/en-us/articles/31194180517916
 *
 * Runs on PHP 5.5 and later.
 *
 * @author    LankaHost Web Solutions (Private) Limited <https://www.lankahost.lk>
 * @copyright Copyright (c) 2026 LankaHost Web Solutions (Private) Limited. All rights reserved.
 * @link      https://www.lankahost.lk
 */

// Avoid "timezone not set" warnings on old PHP versions.
if (!ini_get('date.timezone')) {
    date_default_timezone_set('UTC');
}

const SCRIPT_VERSION = '1.1.0';
const AUTHOR_NAME    = 'LankaHost Web Solutions (Private) Limited';
const AUTHOR_URL     = 'https://www.lankahost.lk';

// Earliest build date of the patched packages (YYYY-MM-DD).
// cPanel built patched ea-php on 20 Oct 2026; CloudLinux alt-php on 21 Oct 2026.
const PATCH_DATE = '2026-10-20';

// Fixed upstream releases per branch.
$fixedUpstream = [
    '8.5' => '8.5.12',
    '8.4' => '8.4.27',
    '8.3' => '8.3.36',
    '8.2' => '8.2.35',
];

// CloudLinux alt-php fixed builds (CloudLinux OS 7, 8 and 9), version-release.
// The PHP version does not change: the fix is a backport in the package release.
$altFixed = [
    '52' => '5.2.17-242', '53' => '5.3.29-220', '54' => '5.4.45-203', '55' => '5.5.38-183',
    '56' => '5.6.40-147', '70' => '7.0.33-148', '71' => '7.1.33-114', '72' => '7.2.34-97',
    '73' => '7.3.33-82',  '74' => '7.4.33-81',  '80' => '8.0.30-69',  '81' => '8.1.34-39',
    '82' => '8.2.34-7',   '83' => '8.3.35-6',   '84' => '8.4.26-5',   '85' => '8.5.11-5',
];

// alt-php versions with no fixed build.
$altNoFix = ['44', '51'];

// ---------------------------------------------------------------------------

/** True if a PHP function exists and is not disabled. */
function fn_enabled($name)
{
    $disabled = array_map('trim', explode(',', (string) ini_get('disable_functions')));
    return function_exists($name) && !in_array($name, $disabled, true);
}

/** @return DateTimeImmutable|null */
function php_build_date()
{
    if (!fn_enabled('phpinfo')) {
        return null;
    }
    ob_start();
    phpinfo(INFO_GENERAL);
    $info = strip_tags((string) ob_get_clean());

    // Web: "Build Date Oct 21 2026 15:02:11"   CLI: "Build Date => Oct 21 2026 15:02:11"
    if (!preg_match('/Build Date\s*(?:=>)?\s*([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{4})/', $info, $m)) {
        return null;
    }
    $d = DateTimeImmutable::createFromFormat('!M j Y', "{$m[1]} {$m[2]} {$m[3]}");
    return $d ?: null;
}

/** Which PHP build is running: type alt|ea|other, ver like "84", and a label. */
function php_flavor()
{
    $paths = implode(' ', array_filter([
        defined('PHP_BINARY') ? PHP_BINARY : '',
        PHP_BINDIR,
        (string) ini_get('extension_dir'),
        (string) php_ini_loaded_file(),
    ]));
    if (preg_match('#/opt/alt/php(\d+)#', $paths, $m)) {
        return ['type' => 'alt', 'ver' => $m[1], 'label' => "CloudLinux alt-php {$m[1]} (PHP Selector)"];
    }
    if (preg_match('#/opt/cpanel/ea-php(\d+)#', $paths, $m)) {
        return ['type' => 'ea', 'ver' => $m[1], 'label' => "cPanel ea-php{$m[1]} (MultiPHP)"];
    }
    return ['type' => 'other', 'ver' => '', 'label' => 'Other / unknown'];
}

/**
 * Does this PHP process still run code that the update replaced on disk?
 * An RPM update installs new files, so old ones still mapped in memory show
 * as "(deleted)" in /proc/self/maps.
 *
 * @return bool|null true = old code in memory, false = current, null = cannot check
 */
function php_stale_code()
{
    $maps = @file_get_contents('/proc/self/maps');
    if ($maps === false || $maps === '') {
        return null;
    }
    foreach (explode("\n", $maps) as $line) {
        if (preg_match('#\s(/\S*php\S*)\s+\(deleted\)\s*$#i', $line)) {
            return true;
        }
    }
    return false;
}

/**
 * CloudLinux's primary check: count CVE mentions in the package changelog.
 * Works only where shell_exec and rpm are available (normally root CLI).
 *
 * @return array|null ['pkg', 'build', 'cves'] or null when not available
 */
function rpm_check(array $flavor)
{
    if ($flavor['type'] === 'other' || !fn_enabled('shell_exec')) {
        return null;
    }
    $pkg = $flavor['type'] === 'alt'
        ? "alt-php{$flavor['ver']}-common"
        : "ea-php{$flavor['ver']}-php-cli";
    $arg   = escapeshellarg($pkg);
    $build = trim((string) @shell_exec("rpm -q --qf '%{VERSION}-%{RELEASE}' $arg 2>/dev/null"));
    if (!preg_match('/^\d+\.\d+/', $build)) {
        return null;
    }
    $count = trim((string) @shell_exec("rpm -q --changelog $arg 2>/dev/null | grep -cE 'CVE-2026-(109618|109619)'"));
    return ['pkg' => $pkg, 'build' => $build, 'cves' => (int) $count];
}

/** Compare "8.4.26-5.el9" with "8.4.26-5": version first, then release number. */
function build_cmp($a, $b)
{
    $pa = explode('-', $a, 2);
    $pb = explode('-', $b, 2);
    $v  = version_compare($pa[0], $pb[0]);
    if ($v !== 0) {
        return $v;
    }
    $ra = isset($pa[1]) ? (int) $pa[1] : 0;
    $rb = isset($pb[1]) ? (int) $pb[1] : 0;
    return $ra === $rb ? 0 : ($ra < $rb ? -1 : 1);
}

// ---------------------------------------------------------------------------

$version  = PHP_VERSION;
$branch   = PHP_MAJOR_VERSION . '.' . PHP_MINOR_VERSION;
$build    = php_build_date();
$patchDay = new DateTimeImmutable(PATCH_DATE);
$flavor   = php_flavor();
$stale    = php_stale_code();
$rpm      = rpm_check($flavor);
$upload   = filter_var(ini_get('session.upload_progress.enabled'), FILTER_VALIDATE_BOOLEAN);
$altBuild = ($flavor['type'] === 'alt' && isset($altFixed[$flavor['ver']])) ? $altFixed[$flavor['ver']] : null;
$built    = $build ? $build->format('j M Y') : null;

if ($flavor['type'] === 'alt' && in_array($flavor['ver'], $altNoFix, true)) {
    $status = 'NO FIX AVAILABLE';
    $reason = "CloudLinux has no fixed build for alt-php {$flavor['ver']}. Switch to a supported PHP version.";
} elseif ($rpm && $rpm['cves'] > 0) {
    $status = 'PATCHED';
    $reason = "Confirmed: the {$rpm['pkg']} {$rpm['build']} package changelog lists the fix.";
} elseif (isset($fixedUpstream[$branch]) && version_compare($version, $fixedUpstream[$branch], '>=')) {
    $status = 'PATCHED';
    $reason = "PHP $version is at or above the fixed release {$fixedUpstream[$branch]}.";
} elseif ($rpm && $altBuild && build_cmp($rpm['build'], $altBuild) >= 0) {
    $status = 'PATCHED';
    $reason = "Package build {$rpm['build']} is at or above CloudLinux's fixed build $altBuild.";
} elseif ($rpm) {
    $status = 'NOT PATCHED';
    $reason = "The {$rpm['pkg']} {$rpm['build']} package changelog does not list the fix. Update PHP.";
} elseif ($altBuild) {
    $base = explode('-', $altBuild, 2);
    $cmp  = version_compare($version, $base[0]);
    if ($cmp > 0) {
        $status = 'PATCHED';
        $reason = "PHP $version is newer than CloudLinux's fixed build $altBuild.";
    } elseif ($cmp < 0) {
        $status = 'NOT PATCHED';
        $reason = "PHP $version is older than CloudLinux's fixed build $altBuild. Contact your host.";
    } elseif ($build && $build >= $patchDay) {
        $status = 'LIKELY PATCHED';
        $reason = "The fix is in build $altBuild or later; the version number does not change. "
                . "PHP was built on $built, which matches the fixed build. Your host can confirm the exact build.";
    } elseif ($build === null) {
        $status = 'UNKNOWN';
        $reason = "The fix is in build $altBuild or later, and the build date could not be read. Ask your host to confirm.";
    } else {
        $status = 'NOT PATCHED';
        $reason = "PHP was built on $built, before the fixed build $altBuild was released. Contact your host.";
    }
} elseif ($build && $build >= $patchDay) {
    $status = 'LIKELY PATCHED';
    $reason = "Version number unchanged, but PHP was built on $built (on or after "
            . $patchDay->format('j M Y') . '), consistent with a backported fix.';
} elseif ($build === null) {
    $status = 'UNKNOWN';
    $reason = 'Could not read the build date (phpinfo may be disabled). Ask your host to confirm.';
} else {
    $status = 'NOT PATCHED';
    $reason = "PHP was built on $built, before the fix. Contact your host.";
}

// Old code still in memory overrides the result: the fix is not active yet.
$baseStatus = $status;
if ($stale === true && $status !== 'NO FIX AVAILABLE') {
    $status = 'RESTART NEEDED';
    $reason = 'PHP was updated on disk, but this PHP process is still running the old code from memory. '
            . 'Ask your host to restart PHP (Apache, PHP-FPM, LSAPI or LiteSpeed lsphp).';
}

// Recommendation for PHP branches that no longer get upstream security support.
// PHP 8.2 receives security fixes until 31 Dec 2026; 8.1 and older are end of life.
$recommendation = null;
if (version_compare($branch, '8.2', '<')) {
    $recommendation = "PHP $branch is end of life and no longer receives official security updates. "
        . 'We recommend switching to PHP 8.3 or 8.4. In cPanel, use Select PHP Version '
        . '(or MultiPHP Manager), then check that your website works. Take a backup first, '
        . 'and if your site or plugins need an older version, contact us for help.';
} elseif ($branch === '8.2') {
    $recommendation = 'PHP 8.2 receives security updates only until 31 Dec 2026. '
        . 'Plan a move to PHP 8.3 or 8.4 before then, using Select PHP Version or MultiPHP Manager in cPanel.';
}

$colors = [
    'PATCHED'          => '#15803d',
    'LIKELY PATCHED'   => '#15803d',
    'UNKNOWN'          => '#b45309',
    'RESTART NEEDED'   => '#b45309',
    'NOT PATCHED'      => '#b91c1c',
    'NO FIX AVAILABLE' => '#b91c1c',
];

$rows = [
    'PHP version' => $version,
    'PHP type'    => $flavor['label'],
];
if ($altBuild) {
    $rows["Fixed build for alt-php {$flavor['ver']}"] = "$altBuild or later";
}
$rows['Package build'] = $rpm ? "{$rpm['pkg']} {$rpm['build']}" : 'Not visible here (normal on shared hosting)';
$rows['Server API']    = PHP_SAPI;
$rows['Build date']    = $built ? $built : 'unavailable';
$rows['Running code']  = $stale === true ? 'Old code still in memory: restart needed'
                       : ($stale === false ? 'Current' : 'Could not check');
if ($status === 'RESTART NEEDED') {
    $rows['Result after restart'] = $baseStatus;
}
$rows['Upload progress tracking'] = $upload ? 'On' : 'Off (interim mitigation applied)';

if (PHP_SAPI === 'cli') {
    echo "Status: $status\n" . wordwrap($reason, 78) . "\n\n";
    foreach ($rows as $k => $v) {
        echo str_pad($k, 30) . ": $v\n";
    }
    if ($recommendation) {
        echo "\nRecommendation: " . wordwrap($recommendation, 76, "\n  ") . "\n";
    }
    echo "\n(c) " . date('Y') . ' ' . AUTHOR_NAME . ' - ' . AUTHOR_URL . ' - v' . SCRIPT_VERSION . "\n";
    exit;
}

header('Content-Type: text/html; charset=utf-8');
header('X-Robots-Tag: noindex, nofollow');
header('Cache-Control: no-store');
$h = function ($s) { return htmlspecialchars((string) $s, ENT_QUOTES, 'UTF-8'); };
?>
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>PHP Patch Check</title>
<style>
  body { font: 16px/1.5 system-ui, sans-serif; background: #f6f7f9; color: #1f2328; margin: 0; padding: 32px 16px; }
  .card { max-width: 560px; margin: 0 auto; background: #fff; border-radius: 10px; padding: 24px; box-shadow: 0 1px 3px rgba(0,0,0,.08); }
  .status { font-size: 1.5rem; font-weight: 700; color: <?= $colors[$status] ?>; margin: 0 0 4px; }
  table { width: 100%; border-collapse: collapse; margin-top: 16px; }
  td { padding: 8px 0; border-top: 1px solid #e5e7eb; vertical-align: top; }
  td:first-child { color: #57606a; width: 45%; padding-right: 12px; }
  .warn { margin-top: 20px; padding: 12px; background: #fff7ed; border-radius: 6px; font-size: .9rem; }
  .rec { margin-top: 20px; padding: 12px; background: #eff6ff; border-left: 4px solid #2563eb; border-radius: 6px; font-size: .9rem; }
  .foot { margin: 20px 0 0; font-size: .8rem; color: #57606a; text-align: center; }
  .foot a { color: inherit; }
  @media (prefers-color-scheme: dark) {
    body { background: #0d1117; color: #e6edf3; }
    .card { background: #161b22; box-shadow: none; }
    td { border-color: #30363d; } td:first-child { color: #8b949e; }
    .warn { background: #3a2a12; }
    .rec { background: #10223d; border-left-color: #3b82f6; }
    .foot { color: #8b949e; }
  }
</style>
</head>
<body>
<div class="card">
  <p class="status"><?= $h($status) ?></p>
  <p><?= $h($reason) ?></p>
  <table>
    <?php foreach ($rows as $k => $v): ?>
      <tr><td><?= $h($k) ?></td><td><?= $h($v) ?></td></tr>
    <?php endforeach; ?>
  </table>
  <?php if ($recommendation): ?>
  <div class="rec"><strong>Recommendation</strong><br><?= $h($recommendation) ?></div>
  <?php endif; ?>
  <div class="warn"><strong>Delete this file now.</strong> It is only meant for a one-time check.</div>
  <p class="foot">&copy; <?= date('Y') ?> <?= $h(AUTHOR_NAME) ?> &middot;
    <a href="<?= $h(AUTHOR_URL) ?>" target="_blank" rel="noopener">www.lankahost.lk</a> &middot; v<?= $h(SCRIPT_VERSION) ?></p>
</div>
</body>
</html>
