<?php

/**
 * Validate release metadata independently of framework behavior coverage.
 *
 * @package samlSSO
 * @version 1.3.2
 * @copyright Copyright (c) 2024 by Chris Gralike
 * @license GPLv3+
 */

declare(strict_types=1);

use GlpiPlugin\Samlsso\Tests\Integration\Context;
use GlpiPlugin\Samlsso\Tests\Integration\ReleaseCatalog;

require_once __DIR__ . '/ReleaseCatalog.php';

return [
    'repository.release_catalog' => [
        'covers' => [],
        'run' => static function (Context $context): void {
            $catalog = simplexml_load_file($context->pluginRoot . '/samlsso.xml');
            $context->assert($catalog !== false, 'Release catalog is not valid XML.');
            $changelog = file_get_contents($context->pluginRoot . '/changelog.md');
            $context->assert(is_string($changelog), 'Cannot load the development changelog.');
            ReleaseCatalog::validate(
                $catalog,
                PLUGIN_SAMLSSO_VERSION,
                $changelog,
                getenv('SAMLSSO_RELEASE_VALIDATION') === '1'
            );
        },
    ],
    'repository.release_policy_rejects_invalid_candidates' => [
        'covers' => [],
        'run' => static function (Context $context): void {
            $xml = '<root><versions><version><num>1.0.0</num>'
                . '<download_url>https://github.com/DonutsNL/samlsso/releases/download/'
                . 'v1.0.0/samlsso.zip</download_url>'
                . '</version></versions></root>';
            $catalog = new SimpleXMLElement($xml);
            ReleaseCatalog::validate($catalog, '1.0.0', '', true);
            ReleaseCatalog::validate($catalog, '1.1.0', '**V1.1.0**', false);
            ReleaseCatalog::validate($catalog, '1.1.0', "**V1.1.0**\r\n", false);
            $invalid = [
                [$catalog, '1.1.0', '**V1.1.0**', true],
                [$catalog, '1.1.0', '', false],
                [$catalog, '0.9.0', '**V0.9.0**', false],
                [new SimpleXMLElement('<root><versions/></root>'), '1.1.0', '**V1.1.0**', false],
                [new SimpleXMLElement(str_replace('samlsso.zip', 'untrusted.zip', $xml)), '1.0.0', '', true],
                [new SimpleXMLElement(str_replace('</versions>', $catalog->versions->version->asXML()
                    . '</versions>', $xml)), '1.0.0', '', true],
            ];
            foreach ($invalid as $candidate) {
                $rejected = false;
                try {
                    ReleaseCatalog::validate(...$candidate);
                } catch (UnexpectedValueException) {
                    $rejected = true;
                }
                $context->assert($rejected, 'An invalid development or release candidate passed the policy gate.');
            }
        },
    ],
];
