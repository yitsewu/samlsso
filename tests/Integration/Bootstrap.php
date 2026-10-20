<?php

/**
 * Bootstrap an explicitly selected, disposable GLPI installation.
 *
 * @package samlSSO
 * @version 1.3.2
 * @copyright Copyright (c) 2024 by Chris Gralike
 * @license GPLv3+
 */

declare(strict_types=1);

use GlpiPlugin\Samlsso\Tests\Integration\Context;

$runtime = realpath((string) getenv('SAMLSSO_GLPI_ROOT'));
if ($runtime === false || !is_file($runtime . '/inc/includes.php')) {
    throw new RuntimeException('SAMLSSO_GLPI_ROOT must identify an installed, disposable GLPI runtime.');
}
if (getenv('SAMLSSO_INTEGRATION_ALLOW_DB') !== '1') {
    throw new RuntimeException('Set SAMLSSO_INTEGRATION_ALLOW_DB=1 to authorize the disposable integration database.');
}

$pluginRoot = realpath(__DIR__ . '/../..');
if (function_exists('xdebug_set_filter')) {
    xdebug_set_filter(XDEBUG_FILTER_CODE_COVERAGE, XDEBUG_PATH_INCLUDE, [realpath($pluginRoot
        . '/src') . DIRECTORY_SEPARATOR, realpath($pluginRoot . '/setup.php'), realpath($pluginRoot . '/hook.php')]);
}
if (realpath($runtime . '/plugins/samlsso') !== $pluginRoot) {
    throw new RuntimeException('The selected runtime/plugins/samlsso must resolve to this checkout.');
}

$_SERVER['REQUEST_URI'] = '/';
$_SERVER['HTTP_HOST'] = 'localhost';
$_SERVER['SERVER_NAME'] = 'localhost';
$_SERVER['SERVER_PORT'] = '80';
$_SERVER['REMOTE_ADDR'] = '127.0.0.1';
$_SERVER['REQUEST_METHOD'] = 'GET';
$_SERVER['SCRIPT_NAME'] = '/index.php';
$_SERVER['PHP_SELF'] = '/index.php';
$_SERVER['DOCUMENT_ROOT'] = $runtime . '/public';

require_once $runtime . '/vendor/autoload.php';
global $kernel;
$kernel = new Glpi\Kernel\Kernel();
$kernel->boot();
require_once $pluginRoot . '/setup.php';
require_once $pluginRoot . '/vendor/autoload.php';
require_once __DIR__ . '/Context.php';

/** Register only plugin classes; GLPI classes always come from the framework autoloader. */
spl_autoload_register(static function (string $class) use ($pluginRoot): void {
    $prefix = 'GlpiPlugin\\Samlsso\\';
    if (str_starts_with($class, $prefix)) {
        $path = $pluginRoot . '/src/' . str_replace('\\', '/', substr($class, strlen($prefix))) . '.php';
        if (is_file($path)) {
            require_once $path;
        }
    }
});

foreach ([Session::class, CommonDBTM::class, User::class, Profile_User::class, RuleCollection::class] as $coreClass) {
    $source = realpath((new ReflectionClass($coreClass))->getFileName());
    $corePrefix = str_replace('\\', '/', $runtime) . '/';
    if ($source === false || !str_starts_with(str_replace('\\', '/', $source), $corePrefix)) {
        throw new RuntimeException('A GLPI core class was replaced outside the selected framework: ' . $coreClass);
    }
}

global $DB, $CFG_GLPI;
if (!isset($DB) || !($DB instanceof DBmysql)) {
    throw new RuntimeException('GLPI did not initialize its real database connection.');
}
if (!str_starts_with((string) $DB->dbdefault, 'samlsso_test_')) {
    throw new RuntimeException('Integration tests require a database named samlsso_test_*.');
}
$CFG_GLPI['url_base'] = 'http://localhost';
$CFG_GLPI['root_doc'] = '';

return new Context($runtime, $pluginRoot);
