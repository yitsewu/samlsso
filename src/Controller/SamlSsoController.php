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

    /**
     * Render the existing logout landing page.
     *
     * @param Request $request Incoming native route request.
     * @return Response Rendered logout page.
     */
    #[SecurityStrategy(Firewall::STRATEGY_NO_CHECK)]
    #[Route(self::SLO_ROUTE, name: self::SLO_NAME)]
    #[Route(self::SLO_ROUTE . self::SLO_PARAM, name: self::SLO_NAME . '_param')]
    public function slo(Request $request): Response
    {
        global $CFG_GLPI;
        /** The existing landing page retains its route signature without interpreting the request. */
        unset($request);
        ob_start();
        \Html::nullHeader('SamlSSO Logout', '/');
        $tplVars = ['loginPath' => $CFG_GLPI['url_base'] . '/index.php?noAuto=1'];
        echo TemplateRenderer::getInstance()->render('@samlsso/loggedOut.html.twig', $tplVars);
        \Html::nullFooter();
        return new Response(ob_get_clean());
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
