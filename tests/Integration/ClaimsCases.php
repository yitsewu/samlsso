<?php

/**
 * Resolve actual parsed SAML attributes and persist claim observations in GLPI.
 *
 * @package samlSSO
 * @version 1.3.2
 * @copyright Copyright (c) 2024 by Chris Gralike
 * @license GPLv3+
 */

declare(strict_types=1);

use GlpiPlugin\Samlsso\Config;
use GlpiPlugin\Samlsso\Config\ClaimMapEntity;
use GlpiPlugin\Samlsso\Config\ConfigEntity;
use GlpiPlugin\Samlsso\LoginFlow\User as SamlUser;
use GlpiPlugin\Samlsso\LoginFlow;
use GlpiPlugin\Samlsso\ObservedClaim;
use GlpiPlugin\Samlsso\RuleSaml;
use GlpiPlugin\Samlsso\Tests\Integration\Context;
use GlpiPlugin\Samlsso\Config\ClaimMapItem;
use GlpiPlugin\Samlsso\ClaimMap;

return [
    'claims.required_defaults_and_presets' => [
        'covers' => [ClaimMapEntity::class . '::getPresets', ClaimMapEntity::class
            . '::validate', ClaimMapEntity::class . '::resolveUserFields'],
        'run' => static function (Context $context): void {
            $presets = ClaimMapEntity::getPresets();
            $context->assert(
                isset($presets['entra_id'], $presets['okta'], $presets['keycloak']),
                'Bundled provider presets were not parsed.'
            );
            $context->same(
                SamlUser::SCHEMA_EMAILADDRESS,
                $presets['entra_id'][ClaimMapItem::FIELD_EMAIL],
                'Entra email preset changed.'
            );
            $provider = $context->createProvider();
            $id = (int) $provider->getDBFields()[ConfigEntity::ID];
            $mapping = new ClaimMapEntity($id);
            $identity = [
                [ClaimMap::TARGET_TYPE => ClaimMapItem::TARGET_TYPE_USER_FIELD,
                     ClaimMap::GLPI_FIELD => ClaimMapItem::FIELD_USERNAME, ClaimMap::SAML_CLAIM => 'subject'],
                [ClaimMap::TARGET_TYPE => ClaimMapItem::TARGET_TYPE_USER_FIELD,
                     ClaimMap::GLPI_FIELD => ClaimMapItem::FIELD_EMAIL, ClaimMap::SAML_CLAIM => 'mail'],
            ];
            $context->same(false, $mapping->save([$identity[0]]), 'A missing email mapping was accepted.');
            $context->assert(isset($mapping->getErrors()['email_required']), 'Missing email has no validation error.');
            $invalid = $identity;
            $invalid[0][ClaimMap::SAML_CLAIM] = '';
            $context->same(false, $mapping->save($invalid), 'An empty username claim mapping was accepted.');
            $invalid[0][ClaimMap::TARGET_TYPE] = 1;
            $invalid[0][ClaimMap::SAML_CLAIM] = 'subject';
            $context->same(false, $mapping->save($invalid), 'A non-string target type was accepted.');
            $context->assert(isset($mapping->getErrors()['mapping_0']), 'Malformed mapping has no row error.');
            $mappings = [...$identity,
                [ClaimMap::TARGET_TYPE => ClaimMapItem::TARGET_TYPE_USER_FIELD,
                     ClaimMap::GLPI_FIELD => ClaimMapItem::FIELD_FIRSTNAME,
                          ClaimMap::SAML_CLAIM => 'given', ClaimMap::DEFAULT_VALUE => 'Fallback',
                               ClaimMap::IS_REQUIRED => 0],
            ];
            $context->assert($mapping->save($mappings), 'Valid identity and fallback mappings were rejected.');
            foreach ([[], ['given' => [str_repeat('A', 300)]]] as $extra) {
                $response = $context->claimResponse($provider, $extra + ['subject' => ['fixture'],
                     'mail' => ['fixture@example.invalid']]);
                $fields = SamlUser::getUserInputFieldsFromSamlClaim($response, $id);
                $context->same(
                    'Fallback',
                    $fields[SamlUser::FIRSTNAME],
                    'Missing or overlength claim bypassed its fallback.'
                );
            }
            $mappings[] = [ClaimMap::TARGET_TYPE => ClaimMapItem::TARGET_TYPE_USER_FIELD,
                 ClaimMap::GLPI_FIELD => ClaimMapItem::FIELD_REALNAME, ClaimMap::SAML_CLAIM => 'family',
                      ClaimMap::IS_REQUIRED => 1];
            $context->assert($mapping->save($mappings), 'Required surname mapping was rejected.');
            $response = $context->claimResponse($provider, ['subject' => ['fixture'],
                 'mail' => ['fixture@example.invalid']]);
            $before = LoginFlow::$throwOnError;
            LoginFlow::$throwOnError = true;
            $rejected = false;
            try {
                SamlUser::getUserInputFieldsFromSamlClaim($response, $id);
            } catch (Exception $error) {
                $rejected = str_contains($error->getMessage(), 'Required user field "realname" is missing');
            } finally {
                LoginFlow::$throwOnError = $before;
            }
            $context->assert($rejected, 'Missing required surname claim was accepted.');
        },
    ],
    'claims.default_fallback_and_observation' => [
        'covers' => [SamlUser::class . '::getUserInputFieldsFromSamlClaim', ClaimMapEntity::class
            . '::resolveUsername', ClaimMapEntity::class . '::resolveEmail', ClaimMapEntity::class
                . '::resolveUserFields', ObservedClaim::class . '::trackClaim'],
        'run' => static function (Context $context): void {
            $provider = $context->createProvider();
            $id = (int) $provider->getDBFields()[ConfigEntity::ID];
            $attributes = [SamlUser::SCHEMA_SURNAME => ["O'Neil & Sons"],
                 SamlUser::SCHEMA_GIVENNAME => ['Fixture'], SamlUser::SCHEMA_GROUPS => ['alpha', 'beta']];
            $response = $context->claimResponse($provider, $attributes);
            $fields = SamlUser::getUserInputFieldsFromSamlClaim($response, $id);
            $context->same('fixture@example.invalid', $fields[SamlUser::NAME], 'NameID fallback changed.');
            $context->same(
                ['fixture@example.invalid'],
                $fields[SamlUser::EMAIL],
                'Email-format NameID fallback changed.'
            );
            $context->same("O'Neil & Sons", $fields[SamlUser::REALNAME], 'Parsed claim was escaped as HTML.');
            $context->same(['alpha', 'beta'], $fields[SamlUser::SAMLGROUPS], 'Multi-value group claims were lost.');
            SamlUser::getUserInputFieldsFromSamlClaim($response, $id);
            $context->same(count($attributes) + 1, count($context->rows(
                ObservedClaim::getTable(),
                [ClaimMap::CONFIGS_ID => $id]
            )), 'Repeated parsing duplicated observed claim keys including NameId.');
        },
    ],
    'claims.custom_mapping_and_rule_criteria' => [
        'covers' => [ClaimMapEntity::class . '::resolveRuleFields', ClaimMapEntity::class
            . '::resolveSingleRuleField', RuleSaml::class . '::getCriterias'],
        'run' => static function (Context $context): void {
            $provider = $context->createProvider();
            $id = (int) $provider->getDBFields()[ConfigEntity::ID];
            $mappings = [
                [ClaimMap::TARGET_TYPE => ClaimMapItem::TARGET_TYPE_USER_FIELD,
                     ClaimMap::GLPI_FIELD => ClaimMapItem::FIELD_USERNAME,
                          ClaimMap::SAML_CLAIM => 'subject', ClaimMap::IS_REQUIRED => 1],
                [ClaimMap::TARGET_TYPE => ClaimMapItem::TARGET_TYPE_USER_FIELD,
                     ClaimMap::GLPI_FIELD => ClaimMapItem::FIELD_EMAIL, ClaimMap::SAML_CLAIM => 'mail',
                          ClaimMap::IS_REQUIRED => 1],
                [ClaimMap::TARGET_TYPE => ClaimMapItem::TARGET_TYPE_RULE_FIELD,
                     ClaimMap::GLPI_FIELD => ClaimMapItem::FIELD_DEPARTMENT,
                          ClaimMap::SAML_CLAIM => 'department_claim', ClaimMap::DEFAULT_VALUE => 'Fallback',
                               ClaimMap::IS_REQUIRED => 0],
            ];
            $mapping = new ClaimMapEntity($id);
            $context->assert($mapping->save($mappings), 'Custom claim mappings were rejected.');
            $attributes = ['subject' => ['fixture@example.invalid'], 'mail' => ['fixture@example.invalid'],
                 'department_claim' => ['Research & QA']];
            $response = $context->claimResponse($provider, $attributes);
            $rules = (new ClaimMapEntity($id))->resolveRuleFields($response, $response->getAttributes());
            $context->same(
                'Research & QA',
                $rules['_saml_rule_fields'][ClaimMapItem::FIELD_DEPARTMENT] ?? null,
                'Custom rule attribute did not resolve.'
            );
            $criteria = (new RuleSaml())->getCriterias();
            $context->assert(
                isset($criteria[ClaimMapItem::FIELD_DEPARTMENT]),
                'Persisted custom mapping is absent from real rule criteria.'
            );
        },
    ],
    'claims.diagnostic_xml_isolation' => [
        'covers' => [ConfigEntity::class . '::updateXmlStructure', ConfigEntity::class . '::anonymizeXml'],
        'run' => static function (Context $context): void {
            $provider = $context->createProvider([ConfigEntity::REQUEST_TIMEOUT => 17,
                 ConfigEntity::INACTIVITY_TIMEOUT => 29]);
            $id = (int) $provider->getDBFields()[ConfigEntity::ID];
            $before = $context->row(Config::getTable(), ['id' => $id]);
            $xml = '<Response xmlns="urn:oasis:names:tc:SAML:2.0:protocol">'
                . '<Assertion xmlns="urn:oasis:names:tc:SAML:2.0:assertion">'
                . '<Subject><NameID>private@example.invalid</NameID></Subject>'
                . '<AttributeStatement><Attribute Name="mail"><AttributeValue>private@example.invalid</AttributeValue>'
                . '</Attribute></AttributeStatement></Assertion></Response>';
            $redacted = ConfigEntity::anonymizeXml($xml);
            $context->assert(
                !str_contains($redacted, 'private@example.invalid'),
                'Diagnostic XML retained personal values.'
            );
            $provider->updateXmlStructure($redacted);
            $after = $context->row(Config::getTable(), ['id' => $id]);
            $context->same($redacted, $after[ConfigEntity::SAML_XML_STRUCTURE], 'Diagnostic XML was not persisted.');
            foreach (
                [ConfigEntity::REQUEST_TIMEOUT, ConfigEntity::INACTIVITY_TIMEOUT,
                 ConfigEntity::IDP_ENTITY_ID, ConfigEntity::IS_ACTIVE] as $field
            ) {
                $context->same($before[$field], $after[$field], 'Diagnostic update rewrote provider configuration: '
                    . $field);
            }
        },
    ],
];
