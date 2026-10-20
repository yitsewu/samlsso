<?php

/**
 * Measured native login and ACS request coverage, including real terminal responses.
 *
 * @package samlSSO
 * @version 1.3.2
 * @copyright Copyright (c) 2024 by Chris Gralike
 * @license GPLv3+
 */

declare(strict_types=1);

use GlpiPlugin\Samlsso\Config\ConfigEntity;
use GlpiPlugin\Samlsso\LoginFlow;
use GlpiPlugin\Samlsso\LoginFlow\Acs;
use GlpiPlugin\Samlsso\LoginFlow\Auth;
use GlpiPlugin\Samlsso\LoginFlow\Meta;
use GlpiPlugin\Samlsso\LoginFlow\User as SamlUser;
use GlpiPlugin\Samlsso\LoginState;
use GlpiPlugin\Samlsso\Tests\Integration\Context;
use GlpiPlugin\Samlsso\Tests\Integration\ProtocolFixtures;
use GlpiPlugin\Samlsso\Tests\Integration\ProtocolHttp;
use Symfony\Component\HttpFoundation\Request;

require_once __DIR__ . '/ProtocolFixtures.php';
require_once __DIR__ . '/ProtocolHttp.php';

$cases = [
    'protocol.flow.native_permissions' => [
        'run' => static function (Context $context): void {
            $context->login($context->createUser());
            $context->same(LoginFlow::canUpdate(), LoginFlow::canCreate(), 'Create must use the native update right.');
            $context->same(LoginFlow::canUpdate(), LoginFlow::canDelete(), 'Delete must use the native update right.');
            $context->same(LoginFlow::canUpdate(), LoginFlow::canPurge(), 'Purge must use the native update right.');
            $context->assert(LoginFlow::getTypeName() !== '', 'The native menu label is empty.');
            $context->assert(LoginFlow::getIcon() !== '', 'The native menu icon is empty.');
        },
        'covers' => array_map(
            static fn(string $name): string => LoginFlow::class . '::' . $name,
            ['canCreate', 'canDelete', 'canPurge', 'getTypeName', 'getIcon']
        ),
    ],
];
foreach (['acs' => '/plugins/samlsso/front/acs/1', 'slo' => '/plugins/samlsso/front/logout/1'] as $name => $path) {
    $cases['protocol.flow.callback_bypass_' . $name] = [
        'run' => static function (Context $context) use ($path): void {
            $before = $context->rows(LoginState::getTable(), []);
            $_SERVER['REQUEST_URI'] = $path;
            (new LoginFlow())->doAuth();
            $context->same(
                $before,
                $context->rows(LoginState::getTable(), []),
                'Callback interception created or changed authentication state.'
            );
        },
        'covers' => [LoginFlow::class . '::doAuth'],
    ];
}
foreach ([true, false] as $exposed) {
    $cases['protocol.metadata.' . ($exposed ? 'exposed' : 'hidden')] = [
        'run' => static function (Context $context) use ($exposed): void {
            $fixture = new ProtocolFixtures($context, ['provider' => [ConfigEntity::DEBUG => (int) $exposed]]);
            $request = new Request([], [], ['idpId' => $fixture->providerId]);
            $response = (new Meta())->getSPMeta($request);
            $context->same(200, $response->getStatusCode(), 'Metadata has the wrong response status.');
            $document = new DOMDocument();
            $context->assert(
                $document->loadXML($response->getContent(), LIBXML_NONET),
                'Metadata response is not XML.'
            );
            $context->same(
                $exposed ? 'EntityDescriptor' : 'xml',
                $document->documentElement->localName,
                'Metadata disclosure setting was ignored.'
            );
            if ($exposed) {
                $context->same(
                    $fixture->settings['sp']['entityId'],
                    $document->documentElement->getAttribute('entityID'),
                    'Metadata has the wrong entity ID.'
                );
            }
        },
        'covers' => [Meta::class . '::getSPMeta'],
    ];
}

$actions = [
    'enforced' => ['status' => 302, 'location' => 'https://idp.example.invalid/sso'],
    'domain' => ['status' => 302, 'location' => 'https://idp.example.invalid/sso'],
    'selected' => ['status' => 302, 'location' => 'https://idp.example.invalid/sso'],
    'bypass' => ['status' => 302, 'location' => 'https://sp.example.invalid/?bypass=1&noAUTO=1'],
    'login_screen' => ['body' => ['Login with external provider', 'saml_buttons']],
    'logout' => ['body' => ['Request identity provider logout', 'Continue with local logout']],
    'logout_enforced' => ['body' => ['Request identity provider logout', 'Go back to GLPI']],
    'slo' => ['status' => 302, 'location' => ProtocolFixtures::IDP_LOGOUT],
    'slo_fallback' => ['status' => 302, 'location' => 'https://sp.example.invalid/'],
    'local' => [],
    'forced' => ['status' => 302, 'location' => 'https://sp.example.invalid/index.php?noAuto=1'],
    'error' => ['status' => 400, 'body' => ['Return to GLPI']],
    'fatal' => ['status' => 403, 'body' => ['Return to GLPI']],
    'acs_success' => ['body' => ['Auth successful', 'http-equiv="refresh"']],
    'acs_proxied' => ['body' => ['Auth successful', 'http-equiv="refresh"']],
    'acs_replay' => ['status' => 400, 'body' => ['Return to GLPI']],
    'acs_phase' => ['status' => 400, 'body' => ['Return to GLPI']],
    'acs_signature' => ['status' => 400, 'body' => ['Return to GLPI']],
    'acs_correlation' => ['status' => 400, 'body' => ['Return to GLPI']],
    'acs_malformed' => ['status' => 400, 'body' => ['Return to GLPI']],
    'acs_malformed_internal' => ['status' => 400, 'body' => ['Return to GLPI']],
    'acs_missing' => ['status' => 400, 'body' => ['Return to GLPI']],
    'acs_missing_provider' => ['status' => 400, 'body' => ['Return to GLPI']],
    'acs_settings' => ['status' => 400, 'body' => ['Return to GLPI']],
'acs_response_write' => ['status' => 400, 'body' => ['Return to GLPI']],
    'acs_phase_write' => ['status' => 400, 'body' => ['Return to GLPI']],
    'acs_phase_changed_after_response' => ['status' => 400, 'body' => ['Return to GLPI']],
];
foreach ($actions as $action => $expectations) {
    $covers = [];
    if (in_array($action, ['enforced', 'domain', 'selected'], true)) {
        $covers = [LoginFlow::class . '::doAuth', LoginFlow::class . '::interceptBypass',
            LoginFlow::class . '::resolveIdpFromLoginForm', LoginFlow::class . '::performSamlIdpRequest'];
    } elseif (in_array($action, ['logout', 'logout_enforced'], true)) {
        $covers = [LoginFlow::class . '::doAuth', LoginFlow::class . '::performLogOff'];
    } elseif ($action === 'login_screen') {
        $covers = [LoginFlow::class . '::showLoginScreen'];
    } elseif ($action === 'error' || $action === 'fatal') {
        $covers = [LoginFlow::class . ($action === 'error' ? '::printError' : '::PrintFatalLoginError')];
    } elseif (str_starts_with($action, 'acs_')) {
        $covers = [Acs::class . '::init'];
        if (
            !in_array($action, [
                'acs_missing', 'acs_malformed', 'acs_malformed_internal',
                'acs_missing_provider', 'acs_settings',
            ], true)
        ) {
            $covers = [...$covers, Acs::class . '::configureProxyVars', Acs::class . '::setupSamlResponse',
                Acs::class . '::fetchRequestState', Acs::class . '::assertSaml', Acs::class . '::validateSamlResponse'];
        }
        if ($action === 'acs_signature') {
            $covers[] = Acs::class . '::validationSuggestion';
        }
        if (in_array($action, ['acs_success', 'acs_proxied'], true)) {
            $covers = [...$covers, LoginFlow::class . '::performGlpiLogin',
                LoginFlow::class . '::performBrowserRedirect',
                Auth::class . '::loadUser', SamlUser::class . '::getUserInputFieldsFromSamlClaim'];
        }
    } else {
        $covers = [LoginFlow::class . '::doAuth'];
    }
    $cases['protocol.http.' . $action] = [
        'run' => static fn(Context $context): array => ProtocolHttp::run($context, $action, $expectations),
        'covers' => $covers,
    ];
}

return $cases;
