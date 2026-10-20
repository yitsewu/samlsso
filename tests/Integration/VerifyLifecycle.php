<?php

/**
 * Verify repeated native installation against an explicitly selected disposable database.
 *
 * @package samlSSO
 * @version 1.3.2
 * @copyright Copyright (c) 2024 by Chris Gralike
 * @license GPLv3+
 */

declare(strict_types=1);

use GlpiPlugin\Samlsso\ClaimMap;
use GlpiPlugin\Samlsso\Config;
use GlpiPlugin\Samlsso\Config\ClaimMapEntity;
use GlpiPlugin\Samlsso\Config\ClaimMapItem;
use GlpiPlugin\Samlsso\Config\ConfigEntity;
use GlpiPlugin\Samlsso\CronTask as SamlCron;
use GlpiPlugin\Samlsso\LoginState;

if (getenv('SAMLSSO_INTEGRATION_PROVISION') !== '1') {
    throw new RuntimeException('Lifecycle verification requires SAMLSSO_INTEGRATION_PROVISION=1.');
}
/** A native installer exit(0) must not turn an incomplete lifecycle gate into success. */
$completed = false;
register_shutdown_function(static function () use (&$completed): void {
    if (!$completed) {
        fwrite(STDERR, "Lifecycle verification ended before normal completion.\n");
        exit(1);
    }
});
error_reporting(E_ALL);
ini_set('display_errors', 'stderr');
ini_set('log_errors', '0');
ini_set('html_errors', '0');
ob_start();
$context = require __DIR__ . '/Bootstrap.php';
require_once $context->pluginRoot . '/hook.php';
$plugin = new Plugin();
if ($plugin->isPluginsExecutionSuspended()) {
    throw new RuntimeException('Resume plugin execution in the disposable GLPI instance before this gate.');
}
foreach ([Config::class, ClaimMap::class, LoginState::class] as $class) {
    $context->assert(
        $context->db()->tableExists($class::getTable()),
        'Install the plugin using Provision.php before verifying preservation across repeated installation.'
    );
}
$plugin->checkPluginState('samlsso');
$context->assert(
    $plugin->getFromDBByCrit(['directory' => 'samlsso']),
    'The native plugin manager cannot find samlsso.'
);
$pluginId = $plugin->getID();

/** DDL commits implicitly, so these fixtures use explicit cleanup instead of Context::begin() transactions. */
$fixtureName = 'Lifecycle ' . bin2hex(random_bytes(12)) . " O'Neil & 臺灣 \\ <fixture>";
$fixtureSessionId = '';
$providerId = 0;
$stateId = 0;
$cronBefore = [];
$failure = null;
$cleanupErrors = [];
$diagnostics = [];
set_error_handler(static function (int $severity, string $message, string $file, int $line) use (&$diagnostics): bool {
    if ((error_reporting() & $severity) === 0) {
        return false;
    }
    $diagnostics[] = $message . ' at ' . $file . ':' . $line;
    throw new ErrorException($message, 0, $severity, $file, $line);
});
try {
    if (session_status() === PHP_SESSION_ACTIVE) {
        session_regenerate_id(true);
    } else {
        session_id('samlsso-lifecycle-' . bin2hex(random_bytes(12)));
        session_start();
    }
    $fixtureSessionId = session_id();
    $_SESSION = [];
    Session::initVars();
    Session::loadLanguage('en_GB');

    /** Persist non-default provider settings and raw text using the actual plugin model. */
    $provider = $context->createProvider([
        ConfigEntity::NAME => $fixtureName,
        ConfigEntity::REQUEST_TIMEOUT => 19,
        ConfigEntity::INACTIVITY_TIMEOUT => 41,
        ConfigEntity::SYNC_ON_LOGIN => 1,
    ]);
    $providerId = (int) $provider->getDBFields()[ConfigEntity::ID];
    $mappings = [
        [
            ClaimMap::TARGET_TYPE => ClaimMapItem::TARGET_TYPE_USER_FIELD,
            ClaimMap::GLPI_FIELD => ClaimMapItem::FIELD_USERNAME,
            ClaimMap::SAML_CLAIM => 'subject',
        ],
        [
            ClaimMap::TARGET_TYPE => ClaimMapItem::TARGET_TYPE_USER_FIELD,
            ClaimMap::GLPI_FIELD => ClaimMapItem::FIELD_EMAIL,
            ClaimMap::SAML_CLAIM => 'mail',
        ],
        [
            ClaimMap::TARGET_TYPE => ClaimMapItem::TARGET_TYPE_USER_FIELD,
            ClaimMap::GLPI_FIELD => ClaimMapItem::FIELD_REALNAME,
            ClaimMap::SAML_CLAIM => 'family_name',
            ClaimMap::DEFAULT_VALUE => "O'Neil & 臺灣 \\ <fixture>",
            ClaimMap::IS_REQUIRED => 0,
        ],
    ];
    $context->assert((new ClaimMapEntity($providerId))->save($mappings), 'Cannot persist lifecycle claim mappings.');

    /** Preserve a correlated SAML authentication state, including replay identifiers and diagnostic history. */
    $_SERVER['REQUEST_URI'] = '/lifecycle-fixture';
    $state = new LoginState();
    $context->assert($state->writeState(), 'Cannot persist lifecycle authentication state.');
    $stateId = $state->getStateId();
    $context->assert($state->setIdpId($providerId), 'Cannot persist the lifecycle state provider.');
    $context->assert($state->setRequestId('_' . bin2hex(random_bytes(16))), 'Cannot persist the lifecycle request ID.');
    $context->assert(
        $state->setSamlResponseId('_' . bin2hex(random_bytes(16))),
        'Cannot persist the lifecycle response ID.'
    );
    $context->assert($state->setSamlAuthTrue(), 'Cannot persist the lifecycle SAML authentication flag.');
    $context->assert($state->setPhase(LoginState::PHASE_SAML_AUTH), 'Cannot persist the lifecycle phase.');
    $context->assert(
        $state->addLoginFlowTrace(['lifecycle' => 'preserve fixture']),
        'Cannot persist the lifecycle trace.'
    );

    /** Keep an administrator-selected cron retention parameter and require exactly the same registered tasks. */
    $cronBefore = $context->rows('glpi_crontasks', ['itemtype' => SamlCron::class]);
    $context->same(2, count($cronBefore), 'The baseline must contain exactly the two native samlsso cron tasks.');
    $cron = new CronTask();
    $context->assert($cron->getFromDBbyName(SamlCron::class, 'cleanSessionSAML'), 'The cleanup cron task is missing.');
    $context->assert($cron->update(['id' => $cron->getID(), 'param' => 47]), 'Cannot customize cron retention.');
    $expectedCron = $context->rows('glpi_crontasks', ['itemtype' => SamlCron::class]);
    $beforeConfig = $context->row(Config::getTable(), [ConfigEntity::ID => $providerId]);
    $beforeMappings = $context->rows(ClaimMap::getTable(), [ClaimMap::CONFIGS_ID => $providerId]);
    $beforeState = $context->row(LoginState::getTable(), [LoginState::STATE_ID => $state->getStateId()]);
    $context->assert($beforeState[LoginState::LOCATION] !== '', 'The location-migration fixture must start nonempty.');

    /** Native install returns void; inspect actual plugin state and persisted data after each complete cycle. */
    for ($iteration = 1; $iteration <= 2; $iteration++) {
        $plugin->install($pluginId);
        $context->assert($plugin->isInstalled('samlsso'), 'Native plugin installation did not complete.');
        $context->assert($plugin->activate($pluginId), 'Native plugin activation failed.');
        $context->assert($plugin->isActivated('samlsso'), 'Native plugin remained inactive.');
        $afterConfig = $context->row(Config::getTable(), [ConfigEntity::ID => $providerId]);
        foreach ($beforeConfig as $field => $value) {
            /** Never include certificate or private-key values in assertion diagnostics. */
            $context->assert($afterConfig[$field] === $value, 'Installation changed provider field: ' . $field);
        }
        $context->same(
            $beforeMappings,
            $context->rows(ClaimMap::getTable(), [ClaimMap::CONFIGS_ID => $providerId]),
            'Installation changed or duplicated persisted claim mappings.'
        );
        $afterState = $context->row(LoginState::getTable(), [LoginState::STATE_ID => $state->getStateId()]);
        foreach ($beforeState as $field => $value) {
            if ($field !== LoginState::LOCATION) {
                $context->assert(
                    $afterState[$field] === $value,
                    'Installation changed authentication field: ' . $field
                );
            }
        }
        /** Existing LoginState migration deliberately clears location, independently of session correlation. */
        $context->same('', $afterState[LoginState::LOCATION], 'Existing location cleanup did not execute.');
        $context->same(
            $expectedCron,
            $context->rows('glpi_crontasks', ['itemtype' => SamlCron::class]),
            'Installation replaced cron parameters or duplicated a scheduled task.'
        );
    }
} catch (Throwable $error) {
    $failure = $error;
} finally {
    /** Restore cron customization and delete only this invocation's uniquely identified synthetic rows. */
    $cleanup = [];
    foreach ($cronBefore as $row) {
        $cleanup[] = static function () use ($context, $row): void {
            $context->assert(
                (new CronTask())->update(['id' => $row['id'], 'param' => $row['param']]),
                'Cannot restore the pre-fixture cron parameter.'
            );
            $restored = $context->row('glpi_crontasks', ['id' => $row['id']]);
            $context->same($row['param'], $restored['param'], 'Cron parameter restoration did not persist.');
        };
    }
    $cleanup[] = static function () use ($context, $fixtureSessionId, $stateId): void {
        if ($fixtureSessionId !== '') {
            $where = $stateId > 0
                ? [LoginState::STATE_ID => $stateId]
                : [LoginState::SESSION_ID => $fixtureSessionId];
            $context->assert($context->db()->delete(LoginState::getTable(), $where), 'Cannot remove lifecycle state.');
            $context->same(
                [],
                $context->rows(LoginState::getTable(), $where),
                'Lifecycle state cleanup was incomplete.'
            );
        }
    };
    $cleanup[] = static function () use ($context, $providerId, $fixtureName): void {
        $where = $providerId > 0 ? [ConfigEntity::ID => $providerId] : [ConfigEntity::NAME => $fixtureName];
        $providerIds = $providerId > 0
            ? [$providerId]
            : array_column($context->rows(Config::getTable(), $where), ConfigEntity::ID);
        foreach ($providerIds as $id) {
            $context->assert(
                $context->db()->delete(ClaimMap::getTable(), [ClaimMap::CONFIGS_ID => $id]),
                'Cannot remove lifecycle claim mappings.'
            );
            $context->assert(
                $context->db()->delete(Config::getTable(), [ConfigEntity::ID => $id]),
                'Cannot remove the lifecycle provider.'
            );
            $context->same(
                [],
                $context->rows(ClaimMap::getTable(), [ClaimMap::CONFIGS_ID => $id]),
                'Lifecycle claim cleanup was incomplete.'
            );
        }
        $context->same(
            [],
            $context->rows(Config::getTable(), $where),
            'Lifecycle provider cleanup was incomplete.'
        );
    };
    foreach ($cleanup as $operation) {
        try {
            $operation();
        } catch (Throwable $error) {
            $cleanupErrors[] = $error->getMessage();
        }
    }
    if (session_status() === PHP_SESSION_ACTIVE) {
        session_destroy();
    }
    restore_error_handler();
    ob_end_clean();
}
if ($cleanupErrors !== [] || $diagnostics !== []) {
    throw new RuntimeException('Lifecycle diagnostics or cleanup failed: ' . implode('; ', [
        ...$diagnostics,
        ...$cleanupErrors,
    ]), 0, $failure);
}
if ($failure !== null) {
    throw $failure;
}
echo 'PASS native lifecycle: two install/activate cycles preserved provider, claim, state and cron data on GLPI '
    . GLPI_VERSION . ".\n";
echo "Lifecycle fixtures removed and original cron parameters restored.\n";
$completed = true;
