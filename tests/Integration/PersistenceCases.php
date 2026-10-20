<?php

/**
 * Verify native state persistence and replay checks using the real database.
 *
 * @package samlSSO
 * @version 1.3.2
 * @copyright Copyright (c) 2024 by Chris Gralike
 * @license GPLv3+
 */

declare(strict_types=1);

use GlpiPlugin\Samlsso\Config\ConfigEntity;
use GlpiPlugin\Samlsso\LoginState;
use GlpiPlugin\Samlsso\Tests\Integration\Context;

return [
    'state.location_and_native_dates' => [
        'covers' => [LoginState::class . '::__construct', LoginState::class . '::getLoggingEntries'],
        'run' => static function (Context $context): void {
            $context->login($context->createUser());
            $provider = $context->createProvider();
            $providerId = (int) $provider->getDBFields()[ConfigEntity::ID];
            $_SERVER['REQUEST_URI'] = 'http://:80';
            $state = new LoginState();
            $context->assert($state->writeState(), 'Cannot persist the invalid-location fixture.');
            $state->setIdpId($providerId);
            $row = $context->row(LoginState::getTable(), ['id' => $state->getStateId()]);
            $context->same('UNKNOWN', $row[LoginState::LOCATION], 'Invalid request location did not use its fallback.');
            $login = '2026-05-30 14:30:00';
            $click = '2026-05-30 14:31:00';
            $context->db()->update(LoginState::getTable(), [LoginState::LOGIN_DATETIME => $login,
                 LoginState::LAST_ACTIVITY => $click], ['id' => $state->getStateId()]);
            $_SESSION['glpidate_format'] = 1;
            $entries = LoginState::getLoggingEntries($providerId);
            $entry = reset($entries);
            $context->same(
                Html::convDateTime($login),
                $entry[LoginState::LOGIN_DATETIME],
                'Stored login date bypassed native formatting.'
            );
            $context->same(
                Html::convDateTime($click),
                $entry[LoginState::LAST_ACTIVITY],
                'Stored activity date bypassed native formatting.'
            );
            $context->assert(
                $entry[LoginState::LOGIN_DATETIME] !== $login,
                'Fixture failed to select a non-database date format.'
            );
        },
    ],
    'state.native_session_expiry_and_idle_timeout' => [
        'covers' => [LoginState::class . '::evalGlpiAuth', LoginState::class
            . '::enforceInactivityTimeout', LoginState::class . '::getLoggingEntries'],
        'run' => static function (Context $context): void {
            $context->login($context->createUser());
            $provider = $context->createProvider([ConfigEntity::INACTIVITY_TIMEOUT => 1]);
            $providerId = (int) $provider->getDBFields()[ConfigEntity::ID];
            $state = new LoginState();
            $context->assert($state->writeState(), 'Cannot create an authenticated state.');
            $state->setIdpId($providerId);
            $state->setPhase(LoginState::PHASE_GLPI_AUTH);
            $state->addLoginFlowTrace(['fixture' => '<b>private</b>']);
            $context->same(
                LoginState::PHASE_GLPI_AUTH,
                (new LoginState())->getPhase(),
                'Live native session was treated as expired.'
            );
            $context->db()->update(LoginState::getTable(), [LoginState::LAST_ACTIVITY => date(
                'Y-m-d H:i:s',
                time() - 600
            )], ['id' => $state->getStateId()]);
            $context->same(
                LoginState::PHASE_TIMED_OUT,
                (new LoginState())->getPhase(),
                'Authenticated native session overwrote its idle timeout.'
            );
            $state->setPhase(LoginState::PHASE_GLPI_AUTH);
            unset($_SESSION[LoginState::SESSION_GLPI_NAME_ACCESSOR], $_SESSION[LoginState::SESSION_VALID_ID_ACCESSOR]);
            $context->same(
                LoginState::PHASE_INITIAL,
                (new LoginState())->getPhase(),
                'Expired native session retained authenticated state.'
            );
            $entries = LoginState::getLoggingEntries($providerId);
            $context->assert(count($entries) === 1, 'Logging query did not load the actual persisted session.');
            $entry = reset($entries);
            $context->assert(
                !str_contains($entry[LoginState::LOGIN_FLOW_TRACE], '<b>private</b>'),
                'Persisted trace was rendered as HTML.'
            );
        },
    ],
    'state.persistence_and_replay' => [
        'covers' => [LoginState::class . '::writeState', LoginState::class . '::setRequestId',
             LoginState::class . '::setSamlResponseId', LoginState::class . '::checkResponseIdUnique',
                  LoginState::class . '::hydrateStoredState'],
        'run' => static function (Context $context): void {
            $provider = $context->createProvider();
            $providerId = (int) $provider->getDBFields()[ConfigEntity::ID];
            $state = new LoginState();
            $context->assert($state->writeState(), 'Cannot persist the initial login state.');
            $context->assert($state->setIdpId($providerId), 'Provider was not persisted.');
            $requestId = '_' . bin2hex(random_bytes(16));
            $responseId = '_' . bin2hex(random_bytes(16));
            $context->assert($state->setRequestId($requestId), 'Request id was not persisted.');
            $context->assert($state->setPhase(LoginState::PHASE_SAML_ACS), 'ACS phase transition failed.');
            $context->assert(
                $state->checkResponseIdUnique($responseId),
                'Fresh assertion is incorrectly marked as replayed.'
            );
            $context->assert($state->setSamlResponseId($responseId), 'Response id was not persisted.');
            $context->same(
                false,
                $state->checkResponseIdUnique($responseId),
                'Persisted assertion was accepted a second time.'
            );
            $reloaded = new LoginState($requestId);
            $context->same(
                $state->getStateId(),
                $reloaded->getStateId(),
                'ACS lookup did not load the persisted state.'
            );
            $context->same($providerId, $reloaded->getIdpId(), 'ACS lookup loaded the wrong provider.');
            $context->same(
                $responseId,
                $reloaded->getSamlResponseId(),
                'ACS response id did not survive database reload.'
            );
        },
    ],
    'state.timeout_persistence' => [
        'covers' => [LoginState::class . '::expireStaleAcsRequests', LoginState::class . '::persistTimeout'],
        'run' => static function (Context $context): void {
            $provider = $context->createProvider([ConfigEntity::REQUEST_TIMEOUT => 1]);
            $state = new LoginState();
            $context->assert($state->writeState(), 'Cannot persist the timeout fixture.');
            $context->assert(
                $state->setIdpId((int) $provider->getDBFields()[ConfigEntity::ID]),
                'Provider update failed.'
            );
            $context->assert($state->setPhase(LoginState::PHASE_SAML_ACS), 'Timeout fixture phase update failed.');
            $context->assert($context->db()->update(
                LoginState::getTable(),
                [LoginState::LOGIN_DATETIME => date('Y-m-d H:i:s', time() - 600)],
                ['id' => $state->getStateId()]
            ), 'Cannot age the fixture.');
            LoginState::expireStaleAcsRequests();
            $row = $context->row(LoginState::getTable(), ['id' => $state->getStateId()]);
            $context->same(
                LoginState::PHASE_TIMED_OUT,
                (int) $row[LoginState::PHASE],
                'Expired ACS state was not written to the database.'
            );
            $context->assert(
                (string) $row[LoginState::LOGIN_FLOW_TRACE] !== '',
                'Timeout has no persisted diagnostic trace.'
            );
        },
    ],
];
