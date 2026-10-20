<?php

/**
 * Exercise SAML logout against the real GLPI session, storage, and renderer.
 *
 * @package samlSSO
 * @version 1.3.2
 * @copyright Copyright (c) 2024 by Chris Gralike
 * @license GPLv3+
 */

declare(strict_types=1);

use GlpiPlugin\Samlsso\Controller\SamlSsoController;
use GlpiPlugin\Samlsso\Config\ConfigEntity;
use GlpiPlugin\Samlsso\LoginState;
use GlpiPlugin\Samlsso\Tests\Integration\Context;
use GlpiPlugin\Samlsso\Tests\Integration\ProtocolFixtures;

require_once __DIR__ . '/ProtocolFixtures.php';

$cases = [];
$accepted = [
    'valid' => [],
    'signed_response' => ['sign_response' => true],
    'signed_response_form_encoding' => [
        'sign_response' => true,
        'provider' => [ConfigEntity::LOWERCASE_URL => 0],
    ],
    'signed_response_special_relay' => ['sign_response' => true, 'relay' => 'space + ~ 驗收'],
    'signed_response_special_relay_form_encoding' => [
        'sign_response' => true,
        'relay' => 'space + ~ 驗收',
        'provider' => [ConfigEntity::LOWERCASE_URL => 0],
    ],
    'rsa_sha384' => ['algorithm' => ProtocolFixtures::RSA_SHA384],
    'rsa_sha512' => ['algorithm' => ProtocolFixtures::RSA_SHA512],
    'proxied' => ['forwarded' => true, 'proxied' => true],
    'proxy_state_restored' => ['initial_proxy' => true],
    'xml_state_restored' => ['xml_errors' => true],
];
$rejected = [
    'unsigned' => ['unsigned' => true],
    'tampered_relay' => ['tampered' => true],
    'wrong_name' => ['xml' => ['name' => 'another-user']],
    'wrong_index' => ['xml' => ['index' => '_another-session']],
    'wrong_issuer' => ['xml' => ['issuer' => 'https://other.example.invalid']],
    'wrong_destination' => ['xml' => ['destination' => 'https://other.example.invalid/logout']],
    'expired' => ['age' => -600],
    'future' => ['age' => 600],
    'missing_context' => ['context' => false],
    'logged_out_request' => ['logged_in' => false],
    'wrong_context_provider' => ['wrong_context_provider' => true],
    'wrong_state_provider' => ['wrong_state_provider' => true],
    'unauthenticated_state' => ['state_authenticated' => false],
    'state_write_failure' => ['phase_write' => false],
    'disabled_provider' => ['active' => false],
    'forwarded_without_trust' => ['forwarded' => true],
    'forwarded_without_trust_restored' => ['forwarded' => true, 'initial_proxy' => true],
    'sha1' => ['algorithm' => ProtocolFixtures::RSA_SHA1],
    'missing_algorithm' => ['algorithm' => null],
    'empty_algorithm' => ['algorithm' => ''],
    'unknown_algorithm' => ['algorithm' => 'urn:unsupported:signature'],
    'array_algorithm' => ['array_algorithm' => true],
    'post_request' => ['method' => 'POST'],
];
foreach ([false, true] as $xmlMode) {
    $suffix = $xmlMode ? '_internal_errors' : '_external_errors';
    $rejected['invalid_payload' . $suffix] = ['payload' => 'not-base64', 'xml_errors' => $xmlMode];
    $rejected['truncated_xml' . $suffix] = [
        'payload' => base64_encode(gzdeflate('<samlp:LogoutRequest')),
        'xml_errors' => $xmlMode,
    ];
}
foreach ([true => $accepted, false => $rejected] as $isAccepted => $variants) {
    foreach ($variants as $name => $options) {
        $cases['protocol.slo.' . $name] = [
            'run' => static function (Context $context) use ($options, $isAccepted): void {
                $fixture = new ProtocolFixtures($context, $options);
                $state = $fixture->loginState($options);
                $fixture->assertLogoutRequest($state, $options, (bool) $isAccepted);
            },
            'covers' => [SamlSsoController::class . '::slo'],
        ];
    }
}
foreach ([false, true] as $loggedIn) {
    foreach ([false, true] as $hasResponse) {
        $cases['protocol.slo.' . ($hasResponse ? 'response_' : 'bare_') . ($loggedIn ? 'logged_in' : 'logged_out')] = [
            'run' => static function (Context $context) use ($loggedIn, $hasResponse): void {
                $fixture = new ProtocolFixtures($context);
                $state = $fixture->loginState(['logged_in' => $loggedIn, 'context' => false]);
                $_GET = $hasResponse ? ['SAMLResponse' => 'untrusted-fixture'] : [];
                $_SERVER['QUERY_STRING'] = http_build_query($_GET);
                $before = $_SESSION;
                $response = $fixture->invokeLogout();
                $context->same($loggedIn ? 400 : 200, $response->getStatusCode(), 'Incorrect inert landing status.');
                $context->same(
                    LoginState::PHASE_GLPI_AUTH,
                    (int) $context->row(LoginState::getTable(), ['id' => $state->getStateId()])[LoginState::PHASE],
                    'An inert landing changed the persisted authentication phase.'
                );
                $context->same(
                    $before['glpiID'] ?? null,
                    $_SESSION['glpiID'] ?? null,
                    'Landing changed native authentication.'
                );
                if (!$loggedIn) {
                    $content = $response->getContent();
                    $context->assert(
                        str_contains($content, 'You are signed out of GLPI.'),
                        'Local status was not rendered.'
                    );
                    $context->assert(
                        str_contains($content, 'index.php?noAuto=1'),
                        'Native landing omitted its login link.'
                    );
                }
            },
            'covers' => [SamlSsoController::class . '::slo'],
        ];
    }
}

return $cases;
