<?php

/**
 * Round-trip an actual JSON export and native uploaded-file restore through GLPI.
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
use GlpiPlugin\Samlsso\Config\ConfigForm;
use GlpiPlugin\Samlsso\Tests\Integration\Context;
use GlpiPlugin\Samlsso\Tests\Integration\ProtocolHttp;
use GlpiPlugin\Samlsso\Config\ClaimMapItem;
use Symfony\Component\HttpFoundation\File\UploadedFile;
use Symfony\Component\HttpFoundation\Request;

require_once __DIR__ . '/ProtocolHttp.php';

return [
    'backup.native_export_restore' => [
        'covers' => [ConfigForm::class . '::exportAllConfigs', ConfigForm::class
            . '::restoreAllConfigs', ConfigForm::class . '::restoreConfigEntry', ConfigForm::class
                . '::buildRestoreRow'],
        'run' => static function (Context $context): array {
            /** GLPI 12 records and validates authenticated browser sessions through its real HTTP lifecycle. */
            if (PHP_SAPI !== 'cgi-fcgi') {
                return ProtocolHttp::run($context, 'native_case:backup.native_export_restore', []);
            }
            $context->login($context->createUser());
            $provider = $context->createProvider([ConfigEntity::NAME => "Research & O'Neil",
                 ConfigEntity::REQUEST_TIMEOUT => 13]);
            $id = (int) $provider->getDBFields()[ConfigEntity::ID];
            $mappings = [
                [ClaimMap::TARGET_TYPE => ClaimMapItem::TARGET_TYPE_USER_FIELD,
                     ClaimMap::GLPI_FIELD => ClaimMapItem::FIELD_USERNAME,
                          ClaimMap::SAML_CLAIM => 'subject', ClaimMap::IS_REQUIRED => 1],
                [ClaimMap::TARGET_TYPE => ClaimMapItem::TARGET_TYPE_USER_FIELD,
                     ClaimMap::GLPI_FIELD => ClaimMapItem::FIELD_EMAIL, ClaimMap::SAML_CLAIM => 'mail',
                          ClaimMap::IS_REQUIRED => 1],
            ];
            $context->assert((new ClaimMapEntity($id))->save($mappings), 'Could not create backup claim fixtures.');
            $form = new ConfigForm();
            $export = $form->invoke(Request::create('/plugins/samlsso/config', 'GET', ['action' => 'backup_all']));
            $context->same(200, $export->getStatusCode(), 'Native export returned an error response.');
            $context->same(
                false,
                $export->headers->has('Content-Length'),
                'Export must let the response stack calculate its size.'
            );
            $payload = json_decode($export->getContent(), true, 512, JSON_THROW_ON_ERROR);
            $context->same('1', $payload['schema_version'], 'Backup schema changed.');
            $payload['configurations'][0]['config']['unrecognized_column'] = 'must not persist';
            $file = tempnam(sys_get_temp_dir(), 'samlsso-native-backup-');
            $context->assert(is_string($file), 'Cannot create the isolated backup file.');
            try {
                file_put_contents($file, json_encode($payload, JSON_THROW_ON_ERROR));
                $request = Request::create(
                    '/plugins/samlsso/config',
                    'POST',
                    ['action' => 'restore_all'],
                    [],
                    ['restore_file' => new UploadedFile(
                        $file,
                        'backup.json',
                        'application/json',
                        UPLOAD_ERR_OK,
                        true
                    )]
                );
                $restored = $form->invoke($request);
                $context->same(
                    302,
                    $restored->getStatusCode(),
                    'Native restore did not return its completion redirect.'
                );
                $row = $context->row(Config::getTable(), ['id' => $id]);
                $context->same("Research & O'Neil", $row[ConfigEntity::NAME], 'Restore corrupted raw provider text.');
                $context->same(13, (int) $row[ConfigEntity::REQUEST_TIMEOUT], 'Restore lost the provider timeout.');
                $context->same(2, count($context->rows(
                    ClaimMap::getTable(),
                    [ClaimMap::CONFIGS_ID => $id]
                )), 'Restore lost claim mappings.');
            } finally {
                if (is_file($file)) {
                    unlink($file);
                }
            }
            return [];
        },
    ],
];
