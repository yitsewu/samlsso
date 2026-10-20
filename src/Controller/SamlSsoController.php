<?php

/**
 *  ------------------------------------------------------------------------
 *  samlSSO
 *
 *  samlSSO was inspired by the initial work of Derrick Smith's
 *  PhpSaml. This project's intend is to address some structural issues
 *  caused by the gradual development of GLPI and the broad amount of
 *  wishes expressed by the community.
 *
 *  Copyright (C) 2024 by Chris Gralike
 *  ------------------------------------------------------------------------
 *
 * LICENSE
 *
 * This file is part of samlSSO plugin for GLPI.
 *
 * samlSSO plugin is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * samlSSO is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with samlSSO. If not, see <http://www.gnu.org/licenses/> or
 * https://choosealicense.com/licenses/gpl-3.0/
 *
 * ------------------------------------------------------------------------
 *
 *  @package    samlSSO
 *  @version    1.3.2
 *  @author     Chris Gralike
 *  @copyright  Copyright (c) 2024 by Chris Gralike
 *  @license    GPLv3+
 *  @see        https://github.com/DonutsNL/samlSSO/readme.md
 *  @link       https://github.com/DonutsNL/samlSSO
 *  @since      1.2.0
 * ------------------------------------------------------------------------
 **/

namespace GlpiPlugin\Samlsso\Controller;

use Glpi\Http\Firewall;
use Glpi\Controller\AbstractController;

/** The controller */
/** Required to decorate the invoke */
use Glpi\Security\Attribute\SecurityStrategy;
/** Required for __invoke */
use Symfony\Component\HttpFoundation\Request;
/** Required for __invoke */
use Symfony\Component\HttpFoundation\Response;
/** Required to register controller route */
use Symfony\Component\Routing\Attribute\Route;
/** Required to call Exclude object */
use GlpiPlugin\Samlsso\Exclude;
/** Required to call Rules object */
use GlpiPlugin\Samlsso\RuleSaml;
use GlpiPlugin\Samlsso\LoginState;
/** Required to call the ACS object */
use GlpiPlugin\Samlsso\LoginFlow\Acs;
/** Required to call Exclude object */
use GlpiPlugin\Samlsso\LoginFlow\Meta;
/** Required to call Config object */
use GlpiPlugin\Samlsso\Config\ConfigForm;
use GlpiPlugin\Samlsso\LoginFlow\LoginFlowForm;
use Glpi\Application\View\TemplateRenderer;
use GlpiPlugin\Samlsso\Config\ConfigEntity;
use OneLogin\Saml2\Auth as SamlAuth;
use OneLogin\Saml2\LogoutRequest;
use OneLogin\Saml2\Settings;
use OneLogin\Saml2\Utils;
use RobRichards\XMLSecLibs\XMLSecurityKey;
use Symfony\Component\HttpFoundation\RedirectResponse;

final class SamlSsoController extends AbstractController
{
    /** ACS route */
    /** Route being registered by __class__ */
    public const ACS_ROUTE      = 'front/acs';
    public const ACS_PARAM      = '/{' . LoginState::IDP_ID . '}';
    /** Route name */
    public const ACS_NAME       = 'samlsso_ACS';

    /** Decorator to disable authentication check */
    #[SecurityStrategy(Firewall::STRATEGY_NO_CHECK)]
    /** Decorator to register route to controller */
    #[Route(self::ACS_ROUTE . self::ACS_PARAM, name: self::ACS_NAME)]
    /**
     * Process an assertion consumer service request.
     *
     * @param Request $request Incoming route request.
     * @return Response Empty response after the ACS handler has completed.
     */
    public function acs(Request $request): Response
    {
        /** Call the ACS handler. */
        (new Acs())->init($request);
        return new Response();
    }

    /** SLO route */
    /** Route being registered by __class__ */
    public const SLO_ROUTE      = 'front/logout';
    public const SLO_PARAM      = '/{' . LoginState::IDP_ID . '}';
    /** Route name */
    public const SLO_NAME       = 'samlsso_SLO';

    /** Signing algorithms supported by this callback without deprecated SHA-1. */
    private const LOGOUT_SIGNATURE_ALGORITHMS = [
        XMLSecurityKey::RSA_SHA256,
        XMLSecurityKey::RSA_SHA384,
        XMLSecurityKey::RSA_SHA512,
    ];

    /**
     * Handle signed IdP logout requests or show an inert local logout page.
     *
     * LogoutResponse correlation is not implemented. An already logged-out browser
     * may see the local completion page, but that page never validates an IdP response.
     * Toolkit XML and proxy settings are scoped to this call, including failures.
     *
     * @param Request $request Incoming logout request.
     * @return Response Protocol redirect, local completion page, or a safe rejection.
     */
    #[SecurityStrategy(Firewall::STRATEGY_NO_CHECK)]
    #[Route(self::SLO_ROUTE, name: self::SLO_NAME)]
    #[Route(self::SLO_ROUTE . self::SLO_PARAM, name: self::SLO_NAME . '_param')]
    public function slo(Request $request): Response
    {
        $previousXmlErrorMode = libxml_use_internal_errors(true);
        $previousProxyMode = Utils::getProxyVars();
        try {
            if (!$request->isMethod('GET')) {
                throw new \UnexpectedValueException('invalid_binding');
            }
            if (
                empty($_SESSION['glpiID'])
                && !array_key_exists('SAMLRequest', $_GET)
                && !array_key_exists('SAMLRequest', $_POST)
            ) {
                return $this->renderLoggedOut();
            }
            return $this->processIdpLogout($request);
        } catch (\Throwable) {
            return new Response(
                __(
                    'The logout request could not be verified. Sign in again or contact your administrator.',
                    PLUGIN_NAME
                ),
                400,
                ['Cache-Control' => 'no-store', 'Content-Type' => 'text/plain; charset=UTF-8']
            );
        } finally {
            libxml_clear_errors();
            libxml_use_internal_errors($previousXmlErrorMode);
            Utils::setProxyVars($previousProxyMode);
        }
    }

    /**
     * Validate an IdP request before allowing native session cleanup.
     *
     * @param Request $request Request carrying the provider route identifier.
     * @return Response Protocol response redirect according to provider settings.
     * @throws \Throwable When configuration, message validation, or logout fails.
     */
    private function processIdpLogout(Request $request): Response
    {
        $idpId = (int) $request->attributes->get(LoginState::IDP_ID, 0);
        $context = $this->requireLogoutContext($idpId);
        $config = new ConfigEntity($idpId);
        if (!$config->isValid() || !$config->isActive()) {
            throw new \UnexpectedValueException('inactive_provider');
        }

        /** Use forwarded origin information only when this provider explicitly enables it. */
        Utils::setProxyVars((bool) $config->getField(ConfigEntity::PROXIED));
        $settingsData = $config->getPhpSamlConfig();
        $settingsData['strict'] = true;
        $settingsData['debug'] = false;
        $settingsData['security']['wantMessagesSigned'] = true;
        $settingsData['security']['wantXMLValidation'] = true;
        $settingsData['security']['relaxDestinationValidation'] = false;
        $logout = new LogoutRequest(new Settings($settingsData), $_GET['SAMLRequest']);
        if (!$logout->isValid(true)) {
            throw new \UnexpectedValueException('invalid_request');
        }
        $this->assertLogoutContext($logout, $context, $settingsData);

        /** Keep database authentication state authoritative before ending the native session. */
        $state = new LoginState();
        if ($state->getIdpId() !== $idpId || !$state->isSamlAuthed()) {
            throw new \UnexpectedValueException('state_mismatch');
        }
        /**
         * The bundled toolkit serializes redirects with urlencode(). Sign the response with the same encoding,
         * including RelayState spaces and tildes. Incoming validation above retains the provider setting, and
         * processSLO reads the original request query bytes through retrieveParametersFromServer=true below.
         */
        $settingsData['security']['lowercaseUrlencoding'] = false;
        $auth = new SamlAuth($settingsData);
        $target = $auth->processSLO(false, null, true, static function () use ($state): void {
            if ($state->setPhase(LoginState::PHASE_LOGOFF) !== true) {
                throw new \UnexpectedValueException('state_update_failed');
            }
            unset($_SESSION['samlsso_slo_context']);
            \Session::cleanOnLogout();
            if (session_status() === PHP_SESSION_ACTIVE) {
                session_regenerate_id(true);
            }
        }, true);
        if ($auth->getErrors() || !is_string($target) || $target === '') {
            throw new \UnexpectedValueException('logout_failed');
        }
        return new RedirectResponse($target, 302, ['Cache-Control' => 'no-store']);
    }

    /**
     * Require a current SAML login and a supported signed Redirect binding.
     *
     * The bundled toolkit does not implement rejectDeprecatedAlgorithm. Check the
     * incoming algorithm explicitly rather than relying on an unused setting.
     *
     * @param int $idpId Provider identifier from the callback route.
     * @return array Validated local correlation context captured during ACS login.
     * @throws \UnexpectedValueException When the context or query is unsupported.
     */
    private function requireLogoutContext(int $idpId): array
    {
        $context = $_SESSION['samlsso_slo_context'] ?? null;
        if (
            $idpId < 1
            || !is_array($context)
            || ($context['idp'] ?? 0) !== $idpId
            || empty($_SESSION['glpiID'])
            || empty($context['name_id'])
            || empty($context['session_index'])
            || !is_string($_GET['SAMLRequest'] ?? null)
            || isset($_GET['SAMLResponse'])
            || empty($_GET['Signature'])
            || strlen($_GET['SAMLRequest']) > 65536
        ) {
            throw new \UnexpectedValueException('missing_context');
        }
        if (!in_array($_GET['SigAlg'] ?? null, self::LOGOUT_SIGNATURE_ALGORITHMS, true)) {
            throw new \UnexpectedValueException('unsupported_signature_algorithm');
        }
        return $context;
    }

    /**
     * Match a cryptographically validated request to this login and configured endpoint.
     *
     * @param LogoutRequest $logout Validated incoming request.
     * @param array $context Local NameID and SessionIndex captured at login.
     * @param array $settingsData Provider and service-provider settings.
     * @return void
     * @throws \UnexpectedValueException When freshness or correlation checks fail.
     */
    private function assertLogoutContext(LogoutRequest $logout, array $context, array $settingsData): void
    {
        $xml = $logout->getXML();
        $dom = new \DOMDocument();
        if (!Utils::loadXML($dom, $xml)) {
            throw new \UnexpectedValueException('invalid_xml');
        }
        $root = $dom->documentElement;
        $issued = Utils::parseSAML2Time($root->getAttribute('IssueInstant'));
        if (
            abs(time() - $issued) > 300
            || $root->getAttribute('Destination') !== $settingsData['sp']['singleLogoutService']['url']
            || LogoutRequest::getIssuer($xml) !== $settingsData['idp']['entityId']
            || !hash_equals((string) $context['name_id'], (string) LogoutRequest::getNameId($xml))
            || !in_array($context['session_index'], LogoutRequest::getSessionIndexes($xml), true)
        ) {
            throw new \UnexpectedValueException('context_mismatch');
        }
    }

    /**
     * Render a local completion page without consuming or validating SAML messages.
     *
     * @return Response An uncached page describing only the absent local login.
     * @throws \Throwable When native page rendering fails.
     */
    private function renderLoggedOut(): Response
    {
        global $CFG_GLPI;

        ob_start();
        try {
            \Html::nullHeader(__('Signed out of GLPI', PLUGIN_NAME), '/');
            echo TemplateRenderer::getInstance()->render('@samlsso/loggedOut.html.twig', [
                'loginPath' => $CFG_GLPI['url_base'] . '/index.php?noAuto=1',
            ]);
            \Html::nullFooter();
            $content = ob_get_contents();
        } finally {
            ob_end_clean();
        }
        return new Response((string) $content, 200, ['Cache-Control' => 'no-store']);
    }

    /** Meta route */
    /** Route being registered by __class__ */
    public const META_ROUTE     = 'front/meta';
    public const META_PARAM     = '/{idpId}';
    /** Route name */
    public const META_NAME      = 'samlsso_META';

    /** Decorator to disable authentication check */
    #[SecurityStrategy(Firewall::STRATEGY_NO_CHECK)]
    /** Decorator to register route to controller */
    #[Route(self::META_ROUTE . self::META_PARAM, name: self::META_NAME)]
    /**
     * Render the service provider metadata.
     *
     * @param Request $request Incoming route request.
     * @return Response XML metadata response.
     */
    public function meta(Request $request): Response
    {
        /** Call the SPMeta handler. */
        return (new Meta())->getSPMeta($request);
    }

    /** Config routes */
    /** Register old route as well */
    public const CONFIG_FILE     = 'front/config.php';
    /** Route being registered by __class__ */
    public const CONFIG_ROUTE    = 'front/config';
    /** Route name */
    public const CONFIG_NAME     = 'configMain';
    /** Parent object name */
    public const CONFIG_PNAME    = 'config';

    /** [SecurityStrategy(Firewall::STRATEGY_NO_CHECK)]                  // Decorator to disable authentication check */
    /** Decorator to register route to controller */
    #[Route(self::CONFIG_ROUTE, name: self::CONFIG_NAME)]
    #[Route(self::CONFIG_FILE, name: self::CONFIG_NAME . '_file')]
    /**
     * Render the identity provider configuration list.
     *
     * @param Request $request Incoming route request.
     * @return Response Rendered list or export response.
     */
    public function config(Request $request): Response
    {
        $res = (new ConfigForm())->invoke($request);
        if ($res instanceof Response) {
            return $res;
        }
        return new Response((string)$res);
    }

    /** ConfigForm routes */
    /** Register old route as well */
    public const CONFIGFORM_FILE = 'front/config.form.php';
    /** Route being registered by __class__ */
    public const CONFIGFORM_ROUTE = 'front/config/form';
    /** Route name */
    public const CONFIGFORM_NAME = 'configForm';
    /** Parent object name */
    public const CONFIGFORM_PNAME = 'config';
    /** [SecurityStrategy(Firewall::STRATEGY_NO_CHECK)]                  // Decorator to disable authentication check */
    /** Decorator to register route to controller */
    #[Route(self::CONFIGFORM_ROUTE, name: self::CONFIGFORM_NAME)]
    #[Route(self::CONFIGFORM_FILE, name: self::CONFIGFORM_NAME . '_file')]
    /**
     * Render or update an identity provider configuration.
     *
     * @param Request $request Incoming route request.
     * @return Response Rendered form or redirect response.
     */
    public function configform(Request $request): Response
    {
        return (new ConfigForm())->invokeForm($request);
    }

    /** LoginFlowConfig */
    public const FLOWFORM_FILE = 'front/loginflow.form.php';
    /** Route being registered by __class__ */
    public const FLOWFORM_ROUTE = 'front/flowconfig';
    /** Route name */
    public const FLOWFORM_NAME = 'flowMain';
    /** Parent object name */
    public const FLOWFORM_PNAME = 'config';
    /** Decorator to disable authentication check */
    #[SecurityStrategy(Firewall::STRATEGY_NO_CHECK)]
    /** Decorator to register route to controller */
    #[Route(self::FLOWFORM_ROUTE, name: self::FLOWFORM_NAME)]
    #[Route(self::FLOWFORM_FILE, name: self::FLOWFORM_NAME . '_file')]
    /**
     * Render the login flow configuration.
     *
     * @return Response Rendered login flow page.
     */
    public function loginflow(): Response
    {
        /** Call the ACS handler. */
        (new LoginFlowForm())->init();
        return new Response();
    }

    /** Exclude routes */
    /** Route being registered by __class__ */
    public const EXCLUDE_ROUTE = 'front/exclude';
    /** Route name */
    public const EXCLUDE_NAME  = 'excludeMain';
    /** Parent object name */
    public const EXCLUDE_PNAME = 'config';
    /** Decorator to disable authentication check */
    #[SecurityStrategy(Firewall::STRATEGY_NO_CHECK)]
    /** Decorator to register route to controller */
    #[Route(self::EXCLUDE_ROUTE, name: self::EXCLUDE_NAME)]
    /**
     * Render the login exclusion configuration.
     *
     * @return Response Rendered exclusions page.
     */
    public function exclude(): Response
    {
        /** Call the ACS handler. */
        (new Exclude())->invoke();
        return new Response();
    }

    /**
     * Rules routes Preserve the file route generated by native GLPI menus.
     */
    public const RULES_FILE     = 'front/rulesaml.php';
    /** Route being registered by __class__ */
    public const RULES_ROUTE    = 'front/rule';
    /** Route name */
    public const RULES_NAME     = 'ruleMain';
    /** Parent object name */
    public const RULES_PNAME    = 'config';
    /** Preserve the form route generated by native GLPI menus. */
    public const RULESFORM_FILE = 'front/rulesaml.form.php';
    /** Route being registered by __class__ */
    public const RULESFORM_ROUTE = 'front/ruleForm';
    /** Route name */
    public const RULESFORM_NAME = 'ruleForm';
    /** Parent object name */
    public const RULESFORM_PNAME = 'config';

    /** Decorator to disable authentication check */
    #[SecurityStrategy(Firewall::STRATEGY_NO_CHECK)]
    /** Decorator to register route to controller */
    #[Route(self::RULES_ROUTE, name: self::RULES_NAME)]
    /** Decorator to register route to controller */
    #[Route(self::RULES_FILE, name: self::RULES_NAME . '_file')]
    /**
     * Render the native SAML rule list.
     *
     * @return Response Rendered rules page.
     */
    public function __invoke(): Response
    {
        /** Call the ACS handler. */
        (new RuleSaml())->invoke();
        return new Response();
    }

    /** Decorator to disable authentication check */
    #[SecurityStrategy(Firewall::STRATEGY_NO_CHECK)]
    /** Decorator to register route to controller */
    #[Route(self::RULESFORM_ROUTE, name: self::RULESFORM_NAME)]
    /** Decorator to register route to controller */
    #[Route(self::RULESFORM_FILE, name: self::RULESFORM_NAME . '_file')]
    /**
     * Render the native SAML rule form.
     *
     * @return Response Rendered rule form.
     */
    public function itemform(): Response
    {
        /** Call the ACS handler. */
        (new RuleSaml())->invokeForm();
        return new Response();
    }
}
