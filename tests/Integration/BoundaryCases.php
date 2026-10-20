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

use GlpiPlugin\Samlsso\Config;
use GlpiPlugin\Samlsso\Config\ConfigEntity;
use GlpiPlugin\Samlsso\Exception\LoginStateException;
use GlpiPlugin\Samlsso\LoginFlow\LoginFlowEntity;
use GlpiPlugin\Samlsso\LoginState;
use GlpiPlugin\Samlsso\Tests\Integration\Context;
use Symfony\Component\HttpFoundation\Request;

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

$cases['boundary.configuration.post_validation'] = [
    'covers' => [LoginFlowEntity::class . '::__construct', LoginFlowEntity::class . '::evaluateItem'],
    'run' => static function (Context $context): void {
        $provider = $context->createProvider([ConfigEntity::DEBUG => 0]);
        $id = (int) $provider->getDBFields()[ConfigEntity::ID];
        $before = $context->row(Config::getTable(), [ConfigEntity::ID => $id]);
        $request = Request::create('/plugins/samlsso/front/loginflow', 'POST', [
            LoginFlowEntity::DEBUG => '1',
            'unrecognized_native_input' => 'ignored',
        ]);
        $entity = new LoginFlowEntity($id, ['template' => 'post', 'postData' => $request->request->all()]);
        $context->assert($entity->isValid(), 'A declared valid POST field was rejected.');
        $context->same(
            '1',
            (string) $entity->getField(LoginFlowEntity::DEBUG),
            'POST data was replaced by stored values.'
        );
        $context->same(
            false,
            $entity->getField('unrecognized_native_input'),
            'An undeclared POST field was imported.'
        );
        $invalid = new LoginFlowEntity($id, [
            'template' => 'post',
            'postData' => [LoginFlowEntity::DEBUG => 'invalid'],
        ]);
        $context->same(false, $invalid->isValid(), 'An invalid declared POST value bypassed validation.');
        $context->assert(
            isset($invalid->getErrorMessages()[LoginFlowEntity::DEBUG]),
            'An invalid POST value has no field-specific validation error.'
        );
        $context->same(
            $before,
            $context->row(Config::getTable(), [ConfigEntity::ID => $id]),
            'Validation wrote to storage.'
        );
    },
];

$cases['boundary.configuration.invalid_options'] = [
    'covers' => [LoginFlowEntity::class . '::__construct'],
    'run' => static function (Context $context): void {
        $provider = $context->createProvider();
        $id = (int) $provider->getDBFields()[ConfigEntity::ID];
        $before = $context->row(Config::getTable(), [ConfigEntity::ID => $id]);
        $rejected = false;
        try {
            new LoginFlowEntity($id, ['template' => 'post', 'postData' => 'invalid']);
        } catch (InvalidArgumentException $error) {
            $rejected = $error->getMessage() === 'Login flow postData must be an array';
        }
        $context->assert($rejected, 'Malformed postData options did not reach the explicit rejection boundary.');
        $context->same(
            $before,
            $context->row(Config::getTable(), [ConfigEntity::ID => $id]),
            'Rejected options wrote data.'
        );
    },
];

$cases['boundary.state.duplicate_correlation'] = [
    'covers' => [LoginState::class . '::getState'],
    'run' => static function (Context $context): void {
        $state = new LoginState();
        $context->assert($state->writeState(), 'Cannot persist the original authentication state.');
        $requestId = '_duplicate_native_' . bin2hex(random_bytes(8));
        $context->assert($state->setRequestId($requestId), 'Cannot persist the correlation identifier.');
        $context->assert($state->setPhase(LoginState::PHASE_SAML_ACS), 'Cannot persist the pending ACS phase.');
        $duplicate = $context->row(LoginState::getTable(), [LoginState::STATE_ID => $state->getStateId()]);
        unset($duplicate[LoginState::STATE_ID]);
        $duplicate[LoginState::SESSION_ID] = 'duplicate-native-' . bin2hex(random_bytes(8));
        $context->assert(
            (bool) $context->db()->insert(LoginState::getTable(), $duplicate),
            'Cannot persist ambiguity.'
        );
        $where = [LoginState::SAML_REQUEST_ID => $requestId];
        $before = $context->rows(LoginState::getTable(), $where);
        $context->same(2, count($before), 'The fixture did not create two matching authentication states.');
        $rejected = false;
        try {
            new LoginState($requestId);
        } catch (LoginStateException $error) {
            $rejected = str_contains($error->getMessage(), 'duplicated states');
        }
        $context->assert($rejected, 'Ambiguous correlation was consumed as one valid authentication state.');
        $context->same(
            $before,
            $context->rows(LoginState::getTable(), $where),
            'Rejected ambiguity modified either row.'
        );
    },
];

return $cases;
