<?php

/**
 * Verify plugin user synchronization through native GLPI objects and persistence.
 *
 * @package samlSSO
 * @version 1.3.2
 * @copyright Copyright (c) 2024 by Chris Gralike
 * @license GPLv3+
 */

declare(strict_types=1);

use GlpiPlugin\Samlsso\Config\ConfigEntity;
use GlpiPlugin\Samlsso\LoginFlow;
use GlpiPlugin\Samlsso\LoginState;
use GlpiPlugin\Samlsso\RuleSaml;
use GlpiPlugin\Samlsso\LoginFlow\User as SamlUser;
use GlpiPlugin\Samlsso\Tests\Integration\Context;

return [
    'user.all_registered_actions_persist' => [
        'covers' => [SamlUser::class . '::updateUserRights', SamlUser::class . '::updateUserDefaults',
             RuleSaml::class . '::getActions'],
        'run' => static function (Context $context): void {
            global $CFG_GLPI;
            $context->login($context->createUser());
            $user = $context->createUser();
            $ids = [];
            foreach (
                [Entity::class, Profile::class, Group::class, Location::class,
                 UserCategory::class, UserTitle::class] as $class
            ) {
                $item = new $class();
                $id = $item->add(['name' => 'Native action ' . bin2hex(random_bytes(5)),
                     'entities_id' => 0, 'interface' => 'central']);
                $context->assert(is_int($id) && $id > 0, 'Native action fixture failed for ' . $class);
                $ids[$class] = $id;
            }
            $values = [
                'entities_id' => $ids[Entity::class],
                'profiles_id' => $ids[Profile::class],
                'is_recursive' => 1,
                'is_active' => 1,
                '_entities_id_default' => $ids[Entity::class],
                'specific_groups_id' => $ids[Group::class],
                'groups_id' => $ids[Group::class],
                '_profiles_id_default' => $ids[Profile::class],
                'timezone' => 'Europe/Amsterdam',
                'locations_id' => $ids[Location::class],
                'usercategories_id' => $ids[UserCategory::class],
                'usertitles_id' => $ids[UserTitle::class],
                'language' => $CFG_GLPI['language'] === 'fr_FR' ? 'de_DE' : 'fr_FR',
            ];
            /** Native engine control actions belong to Rule; every plugin-defined user action must persist. */
            $registered = array_keys(array_diff_key((new RuleSaml())->getActions(), (new Rule())->getActions()));
            $exercised = array_keys($values);
            sort($registered);
            sort($exercised);
            $context->same($registered, $exercised, 'A registered rule action has no native persistence assertion.');
            (new SamlUser())->updateUserRights(['output' => ['users_id' => $user->getID()] + $values]);
            $row = $context->row('glpi_users', ['id' => $user->getID()]);
            foreach (
                ['entities_id', 'profiles_id', 'is_active', 'groups_id', 'locations_id',
                 'usercategories_id', 'usertitles_id'] as $field
            ) {
                $context->same($values[$field], (int) $row[$field], 'Rule action did not persist ' . $field);
            }
            foreach (['timezone', 'language'] as $field) {
                $context->same($values[$field], $row[$field], 'Rule action did not persist ' . $field);
            }
            $relation = $context->row('glpi_profiles_users', ['users_id' => $user->getID()]);
            $context->same(
                $ids[Entity::class],
                (int) $relation['entities_id'],
                'Profile action selected the wrong native entity.'
            );
            $context->same(
                $ids[Profile::class],
                (int) $relation['profiles_id'],
                'Profile action selected the wrong native profile.'
            );
            $context->same(1, (int) $relation['is_recursive'], 'Recursive profile action was lost.');
            $context->row('glpi_groups_users', ['users_id' => $user->getID(), 'groups_id' => $ids[Group::class]]);
        },
    ],
    'user.sync_policy_email_and_trace' => [
        'covers' => [SamlUser::class . '::getOrCreateUser', SamlUser::class . '::compareEmail',
             SamlUser::class . '::traceRulesEngine'],
        'run' => static function (Context $context): void {
            $native = $context->createUser();
            $name = $native->fields['name'];
            $email = $name . '@example.invalid';
            $context->db()->update(
                'glpi_useremails',
                ['email' => strtoupper($email)],
                ['users_id' => $native->getID()]
            );
            $claims = [SamlUser::NAME => $name, SamlUser::EMAIL => [$email], SamlUser::SAMLGROUPS => [],
                 SamlUser::REALNAME => 'Updated fixture'];
            $disabled = $context->createProvider([ConfigEntity::SYNC_ON_LOGIN => 0]);
            $handler = new SamlUser();
            $handler->getOrCreateUser($claims, $disabled);
            $context->same(
                'Integration',
                $context->row('glpi_users', ['id' => $native->getID()])['realname'],
                'Disabled synchronization changed the native user.'
            );
            $enabled = $context->createProvider([ConfigEntity::SYNC_ON_LOGIN => 1]);
            $state = new LoginState();
            $context->assert($state->writeState(), 'Cannot persist synchronization diagnostics.');
            $handler->getOrCreateUser($claims, $enabled, $state);
            $context->same('Updated fixture', $context->row(
                'glpi_users',
                ['id' => $native->getID()]
            )['realname'], 'Enabled synchronization did not persist the claim.');
            $emails = $context->rows('glpi_useremails', ['users_id' => $native->getID()]);
            $context->same(1, count($emails), 'Case-only email difference created a duplicate native relation.');
            $context->same(
                strtoupper($email),
                $emails[0]['email'],
                'Case-only email difference rewrote the existing address.'
            );
            $trace = unserialize($context->row(
                LoginState::getTable(),
                ['id' => $state->getStateId()]
            )[LoginState::LOGIN_FLOW_TRACE], ['allowed_classes' => false]);
            $context->assert(isset(
                $trace['syncUpdatedFields'],
                $trace['rulesEngineInput'],
                $trace['rulesEngineOutput']
            ), 'Synchronization trace was not persisted with rule evaluation.');
            $context->assert(
                str_contains(
                    $trace['syncUpdatedFields'],
                    "realname: 'Integration' => 'Updated fixture'"
                ),
                'Synchronization trace omitted the actual field change.'
            );
            $context->assert(
                !str_contains($trace['syncUpdatedFields'], 'email added'),
                'Case-only email difference was logged as an addition.'
            );
            $handler->getOrCreateUser($claims, $enabled, $state);
            $trace = unserialize($context->row(
                LoginState::getTable(),
                ['id' => $state->getStateId()]
            )[LoginState::LOGIN_FLOW_TRACE], ['allowed_classes' => false]);
            $context->assert(
                isset($trace['syncNoChanges']),
                'Idempotent synchronization did not persist its no-change diagnostic.'
            );
        },
    ],
    'user.native_jit_and_disabled_policy' => [
        'covers' => [SamlUser::class . '::performJIT', SamlUser::class . '::runRulesEngine'],
        'run' => static function (Context $context): void {
            $provider = $context->createProvider([ConfigEntity::USER_JIT => 1]);
            $name = 'samlsso_jit_' . bin2hex(random_bytes(8));
            $claims = [SamlUser::NAME => $name, SamlUser::EMAIL => [$name . '@example.invalid'],
                 SamlUser::REALNAME => "JIT O'Neil & 臺灣 \\ <fixture>", SamlUser::SAMLGROUPS => [], 'is_active' => 1];
            $before = LoginFlow::$throwOnError;
            LoginFlow::$throwOnError = true;
            try {
                $created = (new SamlUser())->getOrCreateUser($claims, $provider);
                $row = $context->row('glpi_users', ['id' => $created->getID()]);
                $context->same($claims[SamlUser::REALNAME], $row['realname'], 'Native JIT changed the raw claim.');
                $context->assert(
                    Profile_User::getForUser($created->getID()) !== [],
                    'Native JIT created a user without an effective profile.'
                );
                $disabledProvider = $context->createProvider([ConfigEntity::USER_JIT => 0]);
                $deniedName = 'samlsso_denied_' . bin2hex(random_bytes(8));
                $denied = false;
                try {
                    (new SamlUser())->getOrCreateUser([SamlUser::NAME => $deniedName,
                         SamlUser::EMAIL => [$deniedName . '@example.invalid']], $disabledProvider);
                } catch (Exception $error) {
                    $denied = str_contains($error->getMessage(), 'disabled');
                }
                $context->assert($denied, 'Disabled JIT did not reject the unknown account.');
                $context->same(
                    [],
                    $context->rows('glpi_users', ['name' => $deniedName]),
                    'Disabled JIT still persisted a user.'
                );
            } finally {
                LoginFlow::$throwOnError = $before;
            }
        },
    ],
    'user.native_profile_replacement' => [
        'covers' => [SamlUser::class . '::assignProfileRights', SamlUser::class
            . '::buildProfileRights', SamlUser::class . '::removeOtherProfiles'],
        'run' => static function (Context $context): void {
            $native = $context->createUser();
            $profile = new Profile();
            $profileId = $profile->add(['name' => 'Native SAML ' . bin2hex(random_bytes(5)), 'interface' => 'central']);
            $context->assert(is_int($profileId) && $profileId > 0, 'Native profile fixture creation failed.');
            $handler = new SamlUser();
            $handler->updateUserRights(['output' => [
                SamlUser::USERSID => $native->getID(),
                SamlUser::PROFILESID => $profileId,
                SamlUser::ENTITY_ID => 0,
                SamlUser::PROFILE_RECURSIVE => 1,
                SamlUser::PROFILE_DEFAULT => $profileId,
                SamlUser::ENTITY_DEFAULT => 0,
            ]]);
            $rows = $context->rows('glpi_profiles_users', ['users_id' => $native->getID()]);
            $context->same(1, count($rows), 'Profile replacement left stale native relations.');
            $context->same($profileId, (int) $rows[0]['profiles_id'], 'Native relation points to the wrong profile.');
            $context->same(1, (int) $rows[0]['is_recursive'], 'Recursive assignment was not persisted.');
            $context->same(
                $profileId,
                (int) $context->row(
                    'glpi_users',
                    ['id' => $native->getID()]
                )['profiles_id'],
                'User default profile does not match the effective assignment.'
            );
        },
    ],
    'user.raw_claim_update' => [
        'covers' => [SamlUser::class . '::getOrCreateUser', SamlUser::class . '::syncUserFieldsOnLogin',
             SamlUser::class . '::compareEmail'],
        'run' => static function (Context $context): void {
            $native = $context->createUser();
            $provider = $context->createProvider([ConfigEntity::SYNC_ON_LOGIN => 1]);
            $name = (string) $native->fields['name'];
            $email = $name . '@example.invalid';
            $claims = [
                SamlUser::NAME => $name,
                SamlUser::EMAIL => [$email],
                SamlUser::SAMLGROUPS => [],
                SamlUser::REALNAME => "O'Neil & Sons <Research> \\ 臺灣",
                SamlUser::FIRSTNAME => 'François "QA" \\ 測試',
            ];
            $found = (new SamlUser())->getOrCreateUser($claims, $provider);
            $context->same((int) $native->getID(), (int) $found->getID(), 'Plugin selected the wrong native user.');
            $stored = $context->row('glpi_users', ['id' => $native->getID()]);
            $context->same(
                $claims[SamlUser::REALNAME],
                $stored['realname'],
                'Raw surname was encoded before native persistence.'
            );
            $context->same(
                $claims[SamlUser::FIRSTNAME],
                $stored['firstname'],
                'Raw first name was encoded before native persistence.'
            );
            $context->same(1, count($context->rows('glpi_useremails', ['users_id' => $native->getID(),
                 'email' => $email])), 'Synchronization duplicated the existing email.');
        },
    ],
    'user.native_group_and_defaults' => [
        'covers' => [SamlUser::class . '::updateUserRights', SamlUser::class . '::assignGroupRights',
             SamlUser::class . '::updateUserDefaults'],
        'run' => static function (Context $context): void {
            global $CFG_GLPI;
            $native = $context->createUser();
            $group = new Group();
            $groupId = $group->add(['name' => 'SAML integration ' . bin2hex(random_bytes(5)), 'entities_id' => 0]);
            $context->assert(is_int($groupId) && $groupId > 0, 'Native group fixture creation failed.');
            $payload = ['output' => [
                SamlUser::USERSID => $native->getID(),
                SamlUser::GROUP_DEFAULT => $groupId,
                SamlUser::GROUPID => $groupId,
                'language' => $CFG_GLPI['language'] === 'fr_FR' ? 'de_DE' : 'fr_FR',
            ]];
            $handler = new SamlUser();
            $handler->updateUserRights($payload);
            $handler->updateUserRights($payload);
            $context->same(1, count($context->rows('glpi_groups_users', ['users_id' => $native->getID(),
                 'groups_id' => $groupId])), 'Native membership was missing or duplicated.');
            $stored = $context->row('glpi_users', ['id' => $native->getID()]);
            $context->same($groupId, (int) $stored['groups_id'], 'Default group was not persisted.');
            $context->same(
                $payload['output']['language'],
                $stored['language'],
                'Explicit non-default language was not persisted.'
            );
            $handler->updateUserRights(['output' => [SamlUser::USERSID => $native->getID(),
                 'language' => $CFG_GLPI['language']]]);
            $context->same(
                null,
                $context->row('glpi_users', ['id' => $native->getID()])['language'],
                'Native GLPI must represent inherited language as SQL NULL.'
            );
            $reloaded = new User();
            $context->assert($reloaded->getFromDB($native->getID()), 'Cannot reload the native user.');
            $reloaded->computePreferences();
            $context->same(
                $CFG_GLPI['language'],
                $reloaded->fields['language'],
                'Native user did not resolve its inherited language.'
            );
        },
    ],
];
