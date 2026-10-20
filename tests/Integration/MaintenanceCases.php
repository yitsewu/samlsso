<?php

/**
 * Verify real database cleanup, request exclusions, and diagnostic rendering.
 *
 * @package samlSSO
 * @version 1.3.2
 * @copyright Copyright (c) 2024 by Chris Gralike
 * @license GPLv3+
 */

declare(strict_types=1);

use GlpiPlugin\Samlsso\Config\ConfigEntity;
use GlpiPlugin\Samlsso\CronTask as SamlCron;
use GlpiPlugin\Samlsso\Exclude;
use GlpiPlugin\Samlsso\LoginState;
use GlpiPlugin\Samlsso\Tests\Integration\Context;
use GlpiPlugin\Samlsso\Utility\LoginTraceRenderer;
use GlpiPlugin\Samlsso\Utility\GeoIPResolver;

return [
    'maintenance.offline_geoip_and_agent_exclusions' => [
        'covers' => [GeoIPResolver::class . '::resolveCountry', GeoIPResolver::class
            . '::searchDatabase', GeoIPResolver::class . '::countryCodeToFlag', GeoIPResolver::class
                . '::countryCodeToName', Exclude::class . '::isExcluded'],
        'run' => static function (Context $context): void {
            $before = GeoIPResolver::getDatabasePath();
            $file = tempnam(sys_get_temp_dir(), 'samlsso-geoip-');
            $context->assert($file !== false, 'Cannot create an offline GeoIP fixture.');
            try {
                $records = pack('NNa2', ip2long('1.1.1.0'), ip2long('1.1.1.255'), 'AU')
                    . pack('NNa2', ip2long('8.8.8.0'), ip2long('8.8.8.255'), 'US')
                    . pack('NNa2', ip2long('81.204.2.0'), ip2long('81.204.2.255'), 'NL');
                $context->same(
                    strlen($records),
                    file_put_contents($file, $records),
                    'Cannot write offline GeoIP ranges.'
                );
                GeoIPResolver::setDatabasePath($file);
                foreach (
                    ['1.1.1.1' => 'AU', '8.8.8.8' => 'US', '81.204.2.126' => 'NL',
                     '127.0.0.1' => '??', 'bad-ip' => '??'] as $ip => $country
                ) {
                    $context->same(
                        $country,
                        GeoIPResolver::resolveCountry($ip),
                        'Offline IP lookup selected the wrong range.'
                    );
                }
                $context->same('Netherlands', GeoIPResolver::countryCodeToName('NL'), 'Country label changed.');
                $context->same('🇳🇱', GeoIPResolver::countryCodeToFlag('NL'), 'Country flag changed.');
                $context->same('', GeoIPResolver::countryCodeToFlag('??'), 'Unknown country produced a flag.');
            } finally {
                GeoIPResolver::setDatabasePath($before);
                unlink($file);
            }
            $result = Exclude::isExcluded();
            $context->assert(
                is_string($result) && str_contains($result, 'Saml auth skipped'),
                'Real CLI process was not excluded.'
            );
            $_SERVER['REQUEST_METHOD'] = 'POST';
            $_SERVER['HTTP_USER_AGENT'] = 'GLPI-Agent_v1.5';
            $_SERVER['REQUEST_URI'] = '/';
            $context->same(true, Exclude::ProcessExcludes(), 'Inventory agent was not excluded.');
        },
    ],
    'maintenance.cron_retention_and_timeout' => [
        'covers' => [SamlCron::class . '::cronCleanSessionSAML'],
        'run' => static function (Context $context): void {
            $provider = $context->createProvider([ConfigEntity::INACTIVITY_TIMEOUT => 1]);
            $state = new LoginState();
            $context->assert($state->writeState(), 'Cannot create the cron fixture.');
            $state->setIdpId((int) $provider->getDBFields()[ConfigEntity::ID]);
            $state->setPhase(LoginState::PHASE_GLPI_AUTH);
            $context->db()->update(LoginState::getTable(), [LoginState::LAST_ACTIVITY => date(
                'Y-m-d H:i:s',
                time() - 600
            )], ['id' => $state->getStateId()]);
            $task = new CronTask();
            $context->assert($task->getFromDBByCrit(['itemtype' => SamlCron::class,
                 'name' => 'CleanSessionSAML']), 'Native scheduled task was not installed.');
            $task->fields['param'] = 0;
            $context->same(0, SamlCron::cronCleanSessionSAML($task), 'Zero retention should not purge session rows.');
            $row = $context->row(LoginState::getTable(), ['id' => $state->getStateId()]);
            $context->same(
                LoginState::PHASE_TIMED_OUT,
                (int) $row[LoginState::PHASE],
                'Cron did not persist the idle timeout.'
            );
            $context->db()->update(LoginState::getTable(), [LoginState::LAST_ACTIVITY => date(
                'Y-m-d H:i:s',
                time() - 86400 * 60
            )], ['id' => $state->getStateId()]);
            $task->fields['param'] = 30;
            $context->same(1, SamlCron::cronCleanSessionSAML($task), 'Positive retention did not run cleanup.');
            $context->same(
                [],
                $context->rows(LoginState::getTable(), ['id' => $state->getStateId()]),
                'Old state survived retention cleanup.'
            );
        },
    ],
    'maintenance.database_exclusion' => [
        'covers' => [Exclude::class . '::ProcessExcludes'],
        'run' => static function (Context $context): void {
            $exclude = new Exclude();
            $context->assert((bool) $exclude->add([
                Exclude::NAME => 'Native API fixture',
                Exclude::CLIENTAGENT => '',
                Exclude::EXCLUDEPATH => '/samlsso-native-fixture/',
                Exclude::ACTION => 1,
            ]), 'Native exclusion persistence failed.');
            $_SERVER['HTTP_USER_AGENT'] = 'SAMLSSO native integration';
            $_SERVER['REQUEST_URI'] = '/samlsso-native-fixture/request';
            $context->same(true, Exclude::ProcessExcludes(), 'Persisted exclusion did not match its path.');
            $_SERVER['REQUEST_URI'] = '/front/central.php';
            $context->same(false, Exclude::ProcessExcludes(), 'Persisted exclusion matched an unrelated path.');
        },
    ],
    'maintenance.trace_rendering' => [
        'covers' => [LoginTraceRenderer::class . '::render'],
        'run' => static function (Context $context): void {
            $trace = serialize(['<fixture>' => '<b>identity</b>',
                 'rulesEngineInput' => json_encode(['name' => '<fixture-user>', 'groups' => ['one', ['two']]])]);
            $html = LoginTraceRenderer::render($trace);
            $context->assert(
                !str_contains($html, '<fixture>') && !str_contains(
                    $html,
                    '<b>identity</b>'
                ) && !str_contains($html, '<fixture-user>'),
                'Diagnostic values were interpreted as HTML.'
            );
            $context->assert(str_contains($html, '&lt;fixture-user&gt;') && str_contains(
                $html,
                'one, two'
            ), 'Trace rendering lost identity values or nested groups.');
        },
    ],
];
