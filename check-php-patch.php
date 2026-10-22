<?php
/**
 * PHP patch check for CVE-2026-109618 / CVE-2026-109619
 *
 * Upload to the site's folder (e.g. public_html) under a hard-to-guess name,
 * open it in a browser, then DELETE IT. Shows only what is needed for the check.
 *
 * Logic:
 *  - PHP 8.2 / 8.3 / 8.4 / 8.5 at or above the fixed upstream release  -> PATCHED
 *  - Otherwise, a build date on or after PATCH_DATE (backported fix,
 *    e.g. CloudLinux alt-php or older ea-php)                         -> LIKELY PATCHED
 *  - Anything else                                                     -> NOT PATCHED
 *
 * @author    LankaHost Web Solutions (Private) Limited <https://www.lankahost.lk>
 * @copyright Copyright (c) 2026 LankaHost Web Solutions (Private) Limited. All rights reserved.
 * @link      https://www.lankahost.lk
 */

// Avoid "timezone not set" warnings on old PHP versions.
if (!ini_get('date.timezone')) {
    date_default_timezone_set('UTC');
}

const AUTHOR_NAME ='LankaHost Web Solutions (Private) Limited';
const AUTHOR_URL  = 'https://www.lankahost.lk';

// Earliest build date of the patched packages on your servers (YYYY-MM-DD).
// cPanel built its patched ea-php packages on 20 Oct 2026 (before the public
// release), e.g. ea-php81 8.1.34 built Oct 20 2026 21:05 with backport EA-13611.
// Hosting team: adjust if your patched alt-php/ea-php builds are dated differently.
const PATCH_DATE = '2026-10-20';

// Fixed upstream releases per branch.
$fixed = [
    '8.5' => '8.5.12',
    '8.4' => '8.4.27',
    '8.3' => '8.3.36',
    '8.2' => '8.2.35',
];

// ---------------------------------------------------------------------------

// Written to run on PHP 5.5 and later, so it also works on old CloudLinux alt-php versions.

/** @return DateTimeImmutable|null */
function php_build_date()
{
    $disabled = array_map('trim', explode(',', (string) ini_get('disable_functions')));
    if (!function_exists('phpinfo') || in_array('phpinfo', $disabled, true)) {
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

/** @return string */
function php_source()
{
    $paths = implode(' ', array_filter([
        PHP_BINARY,
        PHP_BINDIR,
        (string) ini_get('extension_dir'),
        (string) php_ini_loaded_file(),
    ]));
    if (preg_match('#/opt/alt/php(\d+)#', $paths, $m)) {
        return "CloudLinux alt-php {$m[1]} (PHP Selector)";
    }
    if (preg_match('#/opt/cpanel/ea-php(\d+)#', $paths, $m)) {
        return "cPanel ea-php{$m[1]} (MultiPHP)";
    }
    return 'Other / unknown';
}

$version  = PHP_VERSION;
$branch   = PHP_MAJOR_VERSION . '.' . PHP_MINOR_VERSION;
$build    = php_build_date();
$patchDay = new DateTimeImmutable(PATCH_DATE);
$source   = php_source();
$upload   = filter_var(ini_get('session.upload_progress.enabled'), FILTER_VALIDATE_BOOLEAN);

if (isset($fixed[$branch]) && version_compare($version, $fixed[$branch], '>=')) {
    $status = 'PATCHED';
    $reason = "PHP $version is at or above the fixed release {$fixed[$branch]}.";
} elseif ($build && $build >= $patchDay) {
    $status = 'LIKELY PATCHED';
    $reason = 'Version number unchanged, but PHP was built on ' . $build->format('j M Y')
            . ' (on or after ' . $patchDay->format('j M Y') . '), consistent with a backported fix.';
} elseif ($build === null) {
    $status = 'UNKNOWN';
    $reason = 'Could not read the build date (phpinfo may be disabled). Ask your host to confirm.';
} else {
    $status = 'NOT PATCHED';
    $reason = 'PHP was built on ' . $build->format('j M Y') . ', before the fix. Contact your host.';
}

// Recommendation for PHP branches that no longer get upstream security support.
// PHP 8.2 receives security fixes until 31 Dec 2026; 8.1 and older are end of life.
$recommendation = null;
if (version_compare($branch, '8.2', '<')) {
    $recommendation = "PHP $branch is end of life and no longer receives official security updates. "
        . 'We recommend switching to PHP 8.3 or 8.4. In cPanel, use Select PHP Version '
        . ',then check that your website works. Take a backup first '
        . '.';
} elseif ($branch === '8.2') {
    $recommendation = 'PHP 8.2 receives security updates only until 31 Dec 2026. '
        . 'Plan a move to PHP 8.3 or 8.4 before then, using Select PHP Version or MultiPHP Manager in cPanel.';
}

$colors = [
    'PATCHED'        => '#15803d',
    'LIKELY PATCHED' => '#15803d',
    'UNKNOWN'        => '#b45309',
    'NOT PATCHED'    => '#b91c1c',
];

$rows = [
    'PHP version'              => $version,
    'PHP type'                 => $source,
    'Server API'               => PHP_SAPI,
    'Build date'               => $build ? $build->format('j M Y') : 'unavailable',
    'Upload progress tracking' => $upload ? 'On' : 'Off (interim mitigation applied)',
];

if (PHP_SAPI === 'cli') {
    echo "Status: $status\n$reason\n\n";
    foreach ($rows as $k => $v) {
        echo str_pad($k, 26) . ": $v\n";
    }
    if ($recommendation) {
        echo "\nRecommendation: " . wordwrap($recommendation, 76, "\n  ") . "\n";
    }
    echo "\n(c) " . date('Y') . ' ' . AUTHOR_NAME . ' - ' . AUTHOR_URL . "\n";
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
  td:first-child { color: #57606a; width: 45%; }
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
    <a href="<?= $h(AUTHOR_URL) ?>" target="_blank" rel="noopener">www.lankahost.lk</a></p>
</div>
</body>
</html>
