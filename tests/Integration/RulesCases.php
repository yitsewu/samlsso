<?php

/**
 * Exercise the plugin entry points with GLPI's real rule pages and renderer.
 *
 * @package samlSSO
 * @version 1.3.2
 * @copyright Copyright (c) 2024 by Chris Gralike
 * @license GPLv3+
 */

declare(strict_types=1);

use GlpiPlugin\Samlsso\RuleSaml;
use GlpiPlugin\Samlsso\Config\ConfigEntity;
use GlpiPlugin\Samlsso\Config\ClaimMapItem;
use GlpiPlugin\Samlsso\LoginFlow\User as SamlUser;
use GlpiPlugin\Samlsso\Tests\Integration\Context;
use GlpiPlugin\Samlsso\Tests\Integration\ProtocolHttp;

require_once __DIR__ . '/ProtocolHttp.php';

return [
    'rules.native_matching_preserves_claim_aliases' => [
        'covers' => [SamlUser::class . '::runRulesEngine', SamlUser::class . '::updateUserRights'],
        'run' => static function (Context $context): void {
            $context->login($context->createUser());
            $user = $context->createUser();
            $provider = $context->createProvider([ConfigEntity::SYNC_ON_LOGIN => 1]);
            $group = new Group();
            $groupId = $group->add(['name' => 'Rule matched ' . bin2hex(random_bytes(5)), 'entities_id' => 0]);
            $context->assert(is_int($groupId) && $groupId > 0, 'Cannot create the native rule target.');
            $rule = new RuleSaml();
            $ruleId = $rule->add(['name' => 'Native alias match', 'is_active' => 1, 'match' => 'AND']);
            $context->assert(is_int($ruleId) && $ruleId > 0, 'Cannot persist the native matching rule.');
            foreach (
                [SamlUser::SAMLJOBTITLE => 'Engineer', SamlUser::SAMLCOUNTRY => 'NL',
                 SamlUser::SAMLCITY => 'Fixture', SamlUser::SAMLSTREET => 'Main'] as $field => $value
            ) {
                $context->assert(
                    (bool) (new RuleCriteria())->add(['rules_id' => $ruleId,
                     'criteria' => $field, 'condition' => Rule::PATTERN_IS, 'pattern' => $value]),
                    'Cannot persist native rule criteria.'
                );
            }
            $context->assert(
                (bool) (new RuleAction())->add(['rules_id' => $ruleId,
                 'action_type' => 'assign', 'field' => SamlUser::GROUP_DEFAULT, 'value' => $groupId]),
                'Cannot persist the native group rule action.'
            );
            $claims = [
                SamlUser::NAME => $user->fields['name'],
                SamlUser::EMAIL => [$user->fields['name'] . '@example.invalid'],
                SamlUser::SAMLGROUPS => [],
                '_saml_rule_fields' => [ClaimMapItem::FIELD_JOBTITLE => 'Engineer',
                     ClaimMapItem::FIELD_COUNTRY => 'NL', ClaimMapItem::FIELD_CITY => 'Fixture',
                          ClaimMapItem::FIELD_STREET => 'Main'],
            ];
            (new SamlUser())->getOrCreateUser($claims, $provider);
            $context->row('glpi_groups_users', ['users_id' => $user->getID(), 'groups_id' => $groupId]);
        },
    ],
    'rules.native_list_include' => [
        'covers' => [RuleSaml::class . '::invoke'],
        'run' => static function (Context $context): array {
            /** A native CGI session must pass GLPI 12's session tracker before rendering protected pages. */
            if (PHP_SAPI !== 'cgi-fcgi') {
                return ProtocolHttp::run($context, 'native_case:rules.native_list_include', []);
            }
            $context->login($context->createUser());
            ob_start();
            try {
                (new RuleSaml())->invoke();
                $html = ob_get_contents();
            } finally {
                ob_end_clean();
            }
            $context->assert(
                is_string($html) && str_contains($html, '<html'),
                'The actual GLPI rule list did not render a page.'
            );
            $context->assert(
                str_contains($html, 'SAML') || str_contains($html, 'saml'),
                'The actual rule collection was not displayed.'
            );
            return [];
        },
    ],
    'rules.native_form_include' => [
        'covers' => [RuleSaml::class . '::invokeForm', RuleSaml::class . '::getActions',
             RuleSaml::class . '::getCriterias'],
        'run' => static function (Context $context): array {
            /** Keep the form's authorization checks on the same native HTTP path as the rule list. */
            if (PHP_SAPI !== 'cgi-fcgi') {
                return ProtocolHttp::run($context, 'native_case:rules.native_form_include', []);
            }
            $context->login($context->createUser());
            $rule = new RuleSaml();
            $id = $rule->add(['name' => 'Native SAML fixture', 'is_active' => 1, 'match' => 'AND']);
            $context->assert(is_int($id) && $id > 0, 'Native rule creation failed.');
            $_GET['id'] = $id;
            ob_start();
            try {
                $rule->invokeForm();
                $html = ob_get_contents();
            } finally {
                ob_end_clean();
            }
            $context->assert(
                is_string($html) && str_contains($html, 'Native SAML fixture'),
                'The actual GLPI rule form did not load its persisted rule.'
            );
            $context->assert(
                $rule->getActions() !== [] && $rule->getCriterias() !== [],
                'The native rule form has no SAML actions or criteria.'
            );
            return [];
        },
    ],
];
