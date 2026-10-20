<?php

/**
 * Install plugin schema only in the explicitly selected disposable GLPI database.
 *
 * @package samlSSO
 * @version 1.3.2
 * @copyright Copyright (c) 2024 by Chris Gralike
 * @license GPLv3+
 */

declare(strict_types=1);

$context = require __DIR__ . '/Bootstrap.php';
require_once $context->pluginRoot . '/hook.php';
if (getenv('SAMLSSO_INTEGRATION_PROVISION') !== '1') {
    throw new RuntimeException('Schema installation requires SAMLSSO_INTEGRATION_PROVISION=1.');
}
$plugin = new Plugin();
$plugin->checkPluginState('samlsso');
if (!$plugin->getFromDBByCrit(['directory' => 'samlsso'])) {
    throw new RuntimeException('The native plugin manager did not discover this checkout.');
}
$plugin->install($plugin->getID());
if (!$plugin->isInstalled('samlsso') || !$plugin->activate($plugin->getID())) {
    throw new RuntimeException('The native plugin manager could not install and activate samlsso.');
}
echo "Plugin schema installed in the disposable GLPI database.\n";
