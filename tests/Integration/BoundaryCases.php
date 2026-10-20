<?php

/**
 * Verify native URL composition and explicit state/configuration boundaries.
 *
 * @package samlSSO
 * @version 1.3.2
 * @copyright Copyright (c) 2024 by Chris Gralike
 * @license GPLv3+
 */

declare(strict_types=1);

use GlpiPlugin\Samlsso\Tests\Integration\Context;

$cases = [];
foreach (['root' => '', 'subdirectory' => '/helpdesk', 'marketplace_named_root' => '/marketplace'] as $name => $root) {
    $cases['boundary.urls.' . $name] = [
        'covers' => [],
        'run' => static function (Context $context) use ($root): void {
            global $CFG_GLPI;

            /** Real GLPI supplies the runtime; no Plugin class or URL helper is replaced. */
            $CFG_GLPI['root_doc'] = $root;
            $CFG_GLPI['url_base'] = 'https://sp.example.invalid' . $root . '/';
            $expected = $root . '/plugins/samlsso';
            $context->same($expected, samlsso_plugin_web_dir(), 'The native installation prefix was lost.');
            $context->same(
                'https://sp.example.invalid' . $expected . '/',
                samlsso_webdir(),
                'The absolute plugin URL duplicated root_doc or used the physical marketplace namespace.'
            );
            $provider = $context->createProvider();
            $settings = $provider->getPhpSamlConfig();
            $context->assert(
                str_starts_with($settings['sp']['assertionConsumerService']['url'], samlsso_webdir() . 'front/acs/'),
                'The toolkit ACS endpoint did not use the canonical native plugin URL.'
            );
            $context->assert(
                str_starts_with($settings['sp']['singleLogoutService']['url'], samlsso_webdir() . 'front/logout/'),
                'The toolkit logout endpoint did not use the canonical native plugin URL.'
            );
            $CFG_GLPI['url_base'] = '';
            $context->same($expected . '/', samlsso_webdir(), 'Early bootstrap lost its relative URL fallback.');
        },
    ];
}

return $cases;
