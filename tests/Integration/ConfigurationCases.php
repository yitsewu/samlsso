<?php

/**
 * Verify configuration and claim mappings against actual GLPI persistence.
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
use GlpiPlugin\Samlsso\Config\ConfigEntity;
use GlpiPlugin\Samlsso\Config\ConfigItem;
use GlpiPlugin\Samlsso\Config\ConfigForm;
use GlpiPlugin\Samlsso\LoginFlow;
use GlpiPlugin\Samlsso\Tests\Integration\Context;
use GlpiPlugin\Samlsso\Config\ClaimMapItem;

return [
    'configuration.raw_persistence_and_twig_escape' => [
        'covers' => [ConfigForm::class . '::showForm', ConfigForm::class . '::generateForm'],
        'run' => static function (Context $context): void {
            $context->login($context->createUser());
            $payload = "O'Neil & François \\ 臺灣 <native-fixture>\"QA\"</native-fixture>";
            $provider = $context->createProvider([ConfigEntity::NAME => $payload]);
            $id = (int) $provider->getDBFields()[ConfigEntity::ID];
            $context->same(
                $payload,
                $context->row(Config::getTable(), ['id' => $id])[ConfigEntity::NAME],
                'Provider text did not survive native persistence unchanged.'
            );
            $response = (new ConfigForm())->showForm($id);
            $context->same(200, $response->getStatusCode(), 'Native configuration form did not render.');
            $html = $response->getContent();
            $document = (new Masterminds\HTML5(['disable_html_ns' => true]))->loadHTML($html);
            $xpath = new DOMXPath($document);
            $inputs = $xpath->query('//input[@name="name"]');
            $context->same(1, $inputs->length, 'Rendered configuration form has no unambiguous name field.');
            $input = $inputs->item(0);
            if (!$input instanceof DOMElement) {
                throw new RuntimeException('The rendered name field is not an HTML element.');
            }
            $context->same(
                $payload,
                $input->getAttribute('value'),
                'Twig changed the text after HTML attribute decoding.'
            );
            $context->same(
                0,
                $xpath->query('//native-fixture')->length,
                'Stored HTML-looking text became an executable HTML element.'
            );
        },
    ],
    'configuration.certificate_contract' => [
        'covers' => [ConfigItem::class . '::parseX509Certificate', ConfigItem::class . '::validateCertKeyPairModulus'],
        'run' => static function (Context $context): void {
            $otherPem = '';
            $futurePem = '';
            $pair = $context->certificate();
            $validator = new ConfigItem();
            $parse = new ReflectionMethod(ConfigItem::class, 'parseX509Certificate');
            $parsed = $parse->invoke($validator, $pair['certificate']);
            $context->assert(is_array($parsed), 'Fresh real X509 certificate was rejected.');
            $invalid = $parse->invoke($validator, 'not an X509 certificate');
            $context->assert(
                $invalid === false || !empty($invalid['validations']),
                'Malformed certificate was accepted without validation errors.'
            );
            $match = new ReflectionMethod(ConfigItem::class, 'validateCertKeyPairModulus');
            $context->same(true, $match->invoke(
                $validator,
                $pair['certificate'],
                $pair['private_key']
            ), 'Matching certificate/key pair was rejected.');
            $other = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
            $context->assert(
                $other !== false && openssl_pkey_export($other, $otherPem),
                'Cannot create a distinct key fixture.'
            );
            $context->same(
                false,
                $match->invoke($validator, $pair['certificate'], $otherPem),
                'Mismatched certificate/key pair was accepted.'
            );
            $request = openssl_csr_new(['commonName' => 'future.example.invalid'], $other, ['digest_alg' => 'sha256']);
            $context->assert($request !== false, 'Cannot create the long-lived certificate request.');
            $future = openssl_csr_sign($request, null, $other, 10000, ['digest_alg' => 'sha256']);
            $context->assert(
                $future !== false && openssl_x509_export($future, $futurePem),
                'Cannot create the GeneralizedTime certificate.'
            );
            $metadata = openssl_x509_parse($futurePem);
            $context->assert(
                is_array($metadata) && strlen($metadata['validTo']) === 15,
                'Certificate fixture did not exercise GeneralizedTime.'
            );
            $result = $parse->invoke($validator, $futurePem);
            $context->assert(
                is_array($result) && empty($result['validations']),
                'Valid GeneralizedTime certificate was rejected.'
            );
        },
    ],
    'configuration.security_consistency' => [
        'covers' => [ConfigEntity::class . '::validateEnforcedProvider', ConfigEntity::class
            . '::validateInboundSecurity'],
        'run' => static function (Context $context): void {
            $context->createProvider();
            $other = $context->createProvider([ConfigEntity::ENFORCE_SSO => 1]);
            $fields = $other->getFields();
            $context->same(
                0,
                (int) $fields[ConfigEntity::ENFORCE_SSO][ConfigItem::VALUE],
                'Multiple active IdPs retained enforced login.'
            );
            $context->assert(
                !empty($fields[ConfigEntity::ENFORCE_SSO][ConfigItem::ERRORS]),
                'Multiple IdPs produced no configuration warning.'
            );
            $provider = $context->createProvider([ConfigEntity::STRICT => 0,
                 ConfigEntity::SECURITY_WANTMESSAGESSIGNED => 1, ConfigEntity::SECURITY_WANTASSERTIONSSIGNED => 1]);
            $fields = $provider->getFields();
            foreach (
                [ConfigEntity::SECURITY_WANTMESSAGESSIGNED,
                 ConfigEntity::SECURITY_WANTASSERTIONSSIGNED] as $field
            ) {
                $context->same(
                    0,
                    (int) $fields[$field][ConfigItem::VALUE],
                    'Strict-disabled provider kept an ineffective security flag.'
                );
                $context->assert(
                    !empty($fields[$field][ConfigItem::ERRORS]),
                    'Ineffective security flag produced no warning.'
                );
            }
        },
    ],
    'configuration.persist_and_reload' => [
        'covers' => [ConfigEntity::class . '::__construct', ConfigEntity::class
            . '::validateAndPopulateDBEntity', ConfigEntity::class . '::getDBFields'],
        'run' => static function (Context $context): void {
            $provider = $context->createProvider([ConfigEntity::REQUEST_TIMEOUT => 9,
                 ConfigEntity::INACTIVITY_TIMEOUT => 37]);
            $id = (int) $provider->getDBFields()[ConfigEntity::ID];
            $row = $context->row(Config::getTable(), ['id' => $id]);
            $context->same(9, (int) $row[ConfigEntity::REQUEST_TIMEOUT], 'Request timeout was not persisted.');
            $context->same(37, (int) $row[ConfigEntity::INACTIVITY_TIMEOUT], 'Inactivity timeout was not persisted.');
            $reloaded = new ConfigEntity($id);
            $context->same(
                '9',
                $reloaded->getField(ConfigEntity::REQUEST_TIMEOUT),
                'Reloaded request timeout changed.'
            );
            $context->same(
                '37',
                $reloaded->getField(ConfigEntity::INACTIVITY_TIMEOUT),
                'Reloaded inactivity timeout changed.'
            );
            $context->assert($reloaded->isActive(), 'Reloaded provider became inactive.');
        },
    ],
    'configuration.native_rights' => [
        'covers' => [LoginFlow::class . '::canCreate', LoginFlow::class . '::canDelete',
             LoginFlow::class . '::canPurge', LoginFlow::class . '::getTypeName', LoginFlow::class . '::getIcon'],
        'run' => static function (Context $context): void {
            $context->same(false, LoginFlow::canCreate(), 'Anonymous session unexpectedly has configuration rights.');
            $context->same(false, LoginFlow::canDelete(), 'Anonymous session unexpectedly has deletion rights.');
            $context->same(false, LoginFlow::canPurge(), 'Anonymous session unexpectedly has purge rights.');
            $context->login($context->createUser());
            $context->assert(LoginFlow::canCreate() && LoginFlow::canDelete()
                && LoginFlow::canPurge(), 'Real administrator profile cannot manage login configuration.');
            $context->assert(LoginFlow::getTypeName() !== '', 'Translated LoginFlow name is empty.');
            $context->assert(LoginFlow::getIcon() !== '', 'LoginFlow icon is empty.');
        },
    ],
    'configuration.claim_mapping_roundtrip' => [
        'covers' => [ClaimMapEntity::class . '::save', ClaimMapEntity::class . '::validate',
             ClaimMapEntity::class . '::loadFromDB', ClaimMapEntity::class . '::getMapping',
                  ClaimMapEntity::class . '::getDefault', ClaimMapEntity::class . '::isRequired'],
        'run' => static function (Context $context): void {
            $provider = $context->createProvider();
            $id = (int) $provider->getDBFields()[ConfigEntity::ID];
            $mapping = new ClaimMapEntity($id);
            $input = [
                [ClaimMap::TARGET_TYPE => ClaimMapItem::TARGET_TYPE_USER_FIELD,
                     ClaimMap::GLPI_FIELD => ClaimMapItem::FIELD_USERNAME,
                          ClaimMap::SAML_CLAIM => 'subject', ClaimMap::IS_REQUIRED => 0, ClaimMap::DEFAULT_VALUE => ''],
                [ClaimMap::TARGET_TYPE => ClaimMapItem::TARGET_TYPE_USER_FIELD,
                     ClaimMap::GLPI_FIELD => ClaimMapItem::FIELD_EMAIL, ClaimMap::SAML_CLAIM => 'mail',
                          ClaimMap::IS_REQUIRED => 0, ClaimMap::DEFAULT_VALUE => ''],
                [ClaimMap::TARGET_TYPE => ClaimMapItem::TARGET_TYPE_USER_FIELD,
                     ClaimMap::GLPI_FIELD => ClaimMapItem::FIELD_REALNAME,
                          ClaimMap::SAML_CLAIM => 'surname', ClaimMap::IS_REQUIRED => 0,
                               ClaimMap::DEFAULT_VALUE => "O'Neil & Sons"],
            ];
            $context->assert($mapping->save($input), 'Claim mapping save failed.');
            $context->same(
                3,
                count($context->rows(ClaimMap::getTable(), [ClaimMap::CONFIGS_ID => $id])),
                'Not all mappings reached the database.'
            );
            $reloaded = new ClaimMapEntity($id);
            $context->same('subject', $reloaded->getMapping('username'), 'Username mapping was not reloaded.');
            $context->same(
                "O'Neil & Sons",
                $reloaded->getDefault('realname'),
                'Claim fallback was HTML encoded before persistence.'
            );
            $context->assert(
                $reloaded->isRequired('username') && $reloaded->isRequired('email'),
                'Identity mappings must stay required.'
            );
            $invalid = $input;
            $invalid[0][ClaimMap::SAML_CLAIM] = 7;
            $context->same(false, $reloaded->save($invalid), 'Malformed claim must be rejected before persistence.');
            $context->same(
                3,
                count($context->rows(ClaimMap::getTable(), [ClaimMap::CONFIGS_ID => $id])),
                'Rejected mapping modified persisted rows.'
            );
        },
    ],
];
