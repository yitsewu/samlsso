<?php

/**
 * Native request scenarios executed by PHP-CGI, including production exit calls.
 *
 * @package samlSSO
 * @version 1.3.2
 * @copyright Copyright (c) 2024 by Chris Gralike
 * @license GPLv3+
 */

declare(strict_types=1);

namespace GlpiPlugin\Samlsso\Tests\Integration;

use GlpiPlugin\Samlsso\Config\ConfigEntity;
use Glpi\Http\SessionManager;
use Glpi\Kernel\Listener\PostBootListener\SessionStart;
use Glpi\Plugin\Hooks;
use GlpiPlugin\Samlsso\Config;
use GlpiPlugin\Samlsso\LoginFlow;
use GlpiPlugin\Samlsso\LoginFlow\Acs;
use GlpiPlugin\Samlsso\LoginState;
use ReflectionProperty;
use RuntimeException;
use Symfony\Component\HttpFoundation\Request;

/** Scenarios call production methods without subclassing framework or plugin classes. */
final class ProtocolFlowActions
{
    /**
     * Build one request and its observable post-exit verification.
     *
     * @param Context $context Actual framework fixture context.
     * @param string $action Registered scenario name.
     * @return array Invocation, verifier, and expected termination boundary.
     */
    public static function create(Context $context, string $action): array
    {
        if (str_starts_with($action, 'native_case:')) {
            return self::protectedPage($context, substr($action, strlen('native_case:')));
        }
        $provider = [];
        if (in_array($action, ['enforced', 'logout_enforced'], true)) {
            $provider[ConfigEntity::ENFORCE_SSO] = 1;
        }
        if ($action === 'login_screen') {
            $provider[ConfigEntity::CONF_DOMAIN] = '';
        }
        $fixture = new ProtocolFixtures($context, [
            'provider' => $provider,
            'proxied' => $action === 'acs_proxied',
            'forwarded' => $action === 'acs_proxied',
        ]);
        $_SERVER['REQUEST_URI'] = '/index.php';
        $_SERVER['SCRIPT_NAME'] = $_SERVER['PHP_SELF'] = '/index.php';
        $flow = new LoginFlow();
        if (str_starts_with($action, 'acs_')) {
            return self::acs($context, $fixture, $action);
        }
        if (in_array($action, ['logout', 'logout_enforced', 'slo', 'slo_fallback', 'local', 'forced'], true)) {
            $state = $fixture->loginState();
            if ($action === 'slo_fallback') {
                $context->assert($state->setIdpId(998), 'Cannot persist missing provider fixture.');
            }
            if ($action === 'forced') {
                $context->assert($state->setPhase(LoginState::PHASE_FORCE_LOG), 'Cannot persist forced logout.');
            }
            $_SERVER['REQUEST_URI'] = '/front/logout.php';
            if (in_array($action, ['slo', 'slo_fallback'], true)) {
                $_GET[LoginFlow::SLOLOGOUT] = '1';
            } elseif ($action === 'local') {
                $_GET[LoginFlow::LOCALLOGOUT] = '1';
            }
            return [
                'exits' => $action !== 'local',
                'invoke' => static fn() => $flow->doAuth(),
                'verify' => static function () use ($context, $state, $action): void {
                    $chooser = in_array($action, ['logout', 'logout_enforced'], true);
                    $row = $context->row(LoginState::getTable(), ['id' => $state->getStateId()]);
                    $context->same(
                        $chooser ? LoginState::PHASE_GLPI_AUTH : LoginState::PHASE_LOGOFF,
                        (int) $row[LoginState::PHASE],
                        'The logout request persisted an unexpected phase.'
                    );
                    $context->same(
                        $chooser || $action === 'local',
                        !empty($_SESSION['glpiID']),
                        'Native login cleanup boundary is wrong.'
                    );
                },
            ];
        }
        $state = new LoginState();
        $context->assert($state->writeState(), 'Cannot persist initial request state.');
        $context->assert($state->setIdpId($fixture->providerId), 'Cannot persist selected provider.');
        (new ReflectionProperty(LoginFlow::class, 'state'))->setValue($flow, $state);
        LoginFlow::$activeState = $state;
        if (in_array($action, ['enforced', 'domain', 'selected'], true)) {
            if ($action === 'domain') {
                $_POST['login_name'] = 'fixture@example.invalid';
            } elseif ($action === 'selected') {
                $_POST[LoginFlow::POSTFIELD] = $fixture->providerId;
            }
            return [
                'exits' => true,
                'invoke' => static fn() => $flow->doAuth(),
                'verify' => static function () use ($context, $state, $fixture): void {
                    $row = $context->row(LoginState::getTable(), ['id' => $state->getStateId()]);
                    $context->same(
                        LoginState::PHASE_SAML_ACS,
                        (int) $row[LoginState::PHASE],
                        'AuthnRequest did not enter the ACS phase.'
                    );
                    $context->same(
                        $fixture->providerId,
                        (int) $row[LoginState::IDP_ID],
                        'AuthnRequest selected the wrong provider.'
                    );
                    $fresh = new LoginState();
                    $context->assert(
                        $fresh->getSamlRequestId() !== '',
                        'AuthnRequest ID was not persisted before redirect.'
                    );
                    $context->assert(empty($_SESSION['glpiID']), 'An outbound AuthnRequest authenticated locally.');
                },
            ];
        }
        if ($action === 'bypass') {
            $_GET[LoginFlow::SAMLBYPASS] = '1';
            return [
                'exits' => true,
                'invoke' => static fn() => $flow->doAuth(),
                'verify' => static function () use ($context): void {
                    $context->same(
                        true,
                        $_SESSION['glpi_plugins']['samlsso']['bypass'] ?? null,
                        'Bypass flag was not persisted.'
                    );
                    $context->assert(empty($_SESSION['glpiID']), 'Bypass authenticated a user.');
                },
            ];
        }
        if ($action === 'login_screen') {
            return [
                'exits' => false,
                'invoke' => static fn() => $flow->showLoginScreen(),
                'verify' => static function () use ($context): void {
                    $context->assert(empty($_SESSION['glpiID']), 'Rendering a login button authenticated a user.');
                },
            ];
        }
        if (in_array($action, ['error', 'fatal'], true)) {
            return [
                'exits' => true,
                'invoke' => static function () use ($action): never {
                    if ($action === 'fatal') {
                        LoginFlow::PrintFatalLoginError('Native fixture denial');
                    } else {
                        LoginFlow::printError('Native fixture denial', 'native-fixture');
                    }
                    throw new RuntimeException('The terminal authentication handler unexpectedly returned.');
                },
                'verify' => static function () use ($context, $state): void {
                    $row = $context->row(LoginState::getTable(), ['id' => $state->getStateId()]);
                    $context->same(
                        LoginState::PHASE_ERROR,
                        (int) $row[LoginState::PHASE],
                        'Terminal error did not persist the error phase.'
                    );
                    $context->assert(empty($_SESSION['glpiID']), 'Terminal error authenticated locally.');
                },
            ];
        }
        throw new RuntimeException('Unknown native CGI action: ' . $action);
    }

    /**
     * Execute an allowed protected-page case where GLPI records an actual browser session.
     *
     * @param Context $context Actual framework context with an isolated transaction.
     * @param string $name Registered case whose original assertions must complete.
     * @return array Invocation and post-request completion verification.
     * @throws RuntimeException When the requested case is not explicitly supported.
     */
    private static function protectedPage(Context $context, string $name): array
    {
        $suite = match ($name) {
            'backup.native_export_restore' => 'BackupCases.php',
            'rules.native_list_include', 'rules.native_form_include' => 'RulesCases.php',
            default => throw new RuntimeException('Unknown protected-page case: ' . $name),
        };
        $cases = (static fn(string $path): array => require $path)(__DIR__ . '/' . $suite);
        $result = null;
        return [
            'invoke' => static function () use ($cases, $name, $context, &$result): void {
                $result = ($cases[$name]['run'])($context);
            },
            'verify' => static function () use ($context, &$result): void {
                $context->same([], $result, 'The protected page exited before all native assertions completed.');
                $context->same(true, \Session::checkValidSessionId(), 'The native browser session became invalid.');
            },
        ];
    }

    /**
     * Prepare signed ACS responses against real persisted requests and native users.
     *
     * @param Context $context Actual framework context.
     * @param ProtocolFixtures $fixture Independent IdP and SP keys.
     * @param string $action ACS mutation or success scenario.
     * @return array Production invocation and native post-exit verification.
     */
    private static function acs(Context $context, ProtocolFixtures $fixture, string $action): array
    {
        $user = $context->createUser();
        $name = (string) $user->fields['name'];
        $state = new LoginState();
        $context->assert($state->writeState(), 'Cannot persist ACS request.');
        $context->assert($state->setIdpId($fixture->providerId), 'Cannot associate ACS provider.');
        $requestId = '_native_authn_' . bin2hex(random_bytes(8));
        $context->assert($state->setRequestId($requestId), 'Cannot persist AuthnRequest ID.');
        $context->assert($state->setPhase(LoginState::PHASE_SAML_ACS), 'Cannot persist ACS phase.');
        $changes = ['tampered' => $action === 'acs_signature'];
        if ($action === 'acs_correlation') {
            $changes['request'] = '_different_request';
        }
        $body = $fixture->authenticationResponse($requestId, $name, $changes);
        /** XMLSec generates the final signed ID; replay exactly that ID rather than a pre-signing placeholder. */
        $signedDocument = new \DOMDocument();
        $context->assert($signedDocument->loadXML(base64_decode($body)), 'Cannot inspect signed response ID.');
        $responseId = $signedDocument->documentElement->getAttribute('ID');
        if ($action === 'acs_replay') {
            $context->assert($state->setSamlResponseId($responseId), 'Cannot persist consumed response.');
        }
        if ($action === 'acs_phase') {
            $context->assert($state->setPhase(LoginState::PHASE_SAML_AUTH), 'Cannot persist mismatched phase.');
        }
        if ($action === 'acs_settings') {
            $context->assert($context->db()->update(Config::getTable(), [
                ConfigEntity::IDP_SSO_URL => 'not a URL',
            ], ['id' => $fixture->providerId]), 'Cannot persist malformed provider settings fixture.');
        }
        $writeException = false;
        if (in_array($action, ['acs_response_write', 'acs_phase_write'], true)) {
            global $PLUGIN_HOOKS;
            $PLUGIN_HOOKS[Hooks::PRE_ITEM_UPDATE]['samlsso'][LoginState::class] =
                static function (\CommonDBTM $item) use ($state, $responseId, $action, &$writeException): void {
                    if ($writeException || (int) ($item->input[LoginState::STATE_ID] ?? 0) !== $state->getStateId()) {
                        return;
                    }
                    $phase = (int) ($item->input[LoginState::PHASE] ?? 0);
                    $matches = $action === 'acs_phase_write'
                        ? $phase === LoginState::PHASE_SAML_AUTH
                        : $phase === LoginState::PHASE_SAML_ACS
                            && ($item->input[LoginState::SAML_RESPONSE_ID] ?? '') === $responseId;
                    if ($matches) {
                        $writeException = true;
                        throw new RuntimeException('Native fixture hook rejected authentication persistence.');
                    }
                };
        }
        if ($action === 'acs_phase_changed_after_response') {
            global $PLUGIN_HOOKS;
            $PLUGIN_HOOKS[Hooks::ITEM_UPDATE]['samlsso'][LoginState::class] =
                static function (\CommonDBTM $item) use ($state, $responseId, &$writeException): void {
                    if (!$item instanceof LoginState) {
                        throw new RuntimeException('The native state hook received an unexpected item type.');
                    }
                    if (
                        !$writeException
                        && $item->getStateId() === $state->getStateId()
                        && $item->getSamlResponseId() === $responseId
                    ) {
                        $writeException = true;
                        $item->setPhase(LoginState::PHASE_SAML_AUTH);
                    }
                };
        }
        $malformed = in_array($action, ['acs_malformed', 'acs_malformed_internal'], true);
        $xmlMode = $action === 'acs_malformed_internal';
        if ($malformed) {
            $body = base64_encode('<invalid');
        }
        $_SERVER['REQUEST_URI'] = parse_url($fixture->settings['sp']['assertionConsumerService']['url'], PHP_URL_PATH);
        $_SERVER['REQUEST_METHOD'] = 'POST';
        $request = new Request(
            [],
            $action === 'acs_missing' ? [] : ['SAMLResponse' => $body],
            [LoginState::IDP_ID => $action === 'acs_missing_provider' ? 998 : $fixture->providerId],
            [],
            [],
            $_SERVER
        );
        /** End the preceding browser request, then execute the core's real stateless ACS session listener. */
        $_POST = $request->request->all();
        $_REQUEST = $_POST;
        session_write_close();
        $sessionManager = new SessionManager();
        $context->assert($sessionManager->isResourceStateless($request), 'The registered ACS route is not stateless.');
        (new SessionStart($sessionManager, GLPI_ROOT))->onPostBoot();
        $context->same(PHP_SESSION_NONE, session_status(), 'Native ACS listener unexpectedly started a session.');
        $success = in_array($action, ['acs_success', 'acs_proxied'], true);
        return [
            'exits' => true,
            'invoke' => static function () use ($request, $malformed, $xmlMode): void {
                if ($malformed) {
                    libxml_use_internal_errors($xmlMode);
                }
                (new Acs())->init($request);
            },
            'verify' => static function () use (
                $context,
                $state,
                $user,
                $success,
                $action,
                $responseId,
                $malformed,
                $xmlMode,
                &$writeException
            ): void {
                $row = $context->row(LoginState::getTable(), ['id' => $state->getStateId()]);
                if ($malformed) {
                    $context->same($xmlMode, libxml_use_internal_errors(), 'ACS did not restore the XML error mode.');
                    $context->same([], libxml_get_errors(), 'ACS retained parser diagnostics.');
                }
                if ($success) {
                    $context->same(
                        (int) $user->getID(),
                        (int) \Session::getLoginUserID(),
                        'Validated ACS did not initialize native GLPI login.'
                    );
                    $context->same(
                        LoginState::PHASE_GLPI_AUTH,
                        (int) $row[LoginState::PHASE],
                        'Successful ACS did not reach native authentication.'
                    );
                    $fresh = new LoginState();
                    $context->same(
                        $responseId,
                        $fresh->getSamlResponseId(),
                        'Successful ACS did not consume its response ID.'
                    );
                } else {
                    $context->assert(empty($_SESSION['glpiID']), 'Rejected ACS authenticated a native user.');
                    if (
                        !in_array($action, [
                            'acs_correlation', 'acs_missing', 'acs_malformed', 'acs_malformed_internal',
                            'acs_duplicate_state',
                            'acs_settings', 'acs_missing_provider',
                        ], true)
                    ) {
                        $context->same(
                            LoginState::PHASE_ERROR,
                            (int) $row[LoginState::PHASE],
                            'Rejected ACS did not enter the native error phase.'
                        );
                    }
                }
                if (
                    in_array($action, [
                        'acs_response_write', 'acs_phase_write', 'acs_phase_changed_after_response',
                    ], true)
                ) {
                    $context->assert($writeException, 'Native state transition hook was not exercised.');
                }
            },
        ];
    }
}
