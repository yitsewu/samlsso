<?php

/* phpcs:disable PSR1.Files.SideEffects.FoundWithSymbols -- Native entry point combines bootstrap and plugin declarations. */

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
 *  @since      1.0.0
 * ------------------------------------------------------------------------
 **/

/**
 * USE This file is included in the GLPI\Plugins context.
 */
use Glpi\Plugin\Hooks;
use Glpi\Http\SessionManager;
use GlpiPlugin\Samlsso\Config;
use GlpiPlugin\Samlsso\LoginFlow;
use GlpiPlugin\Samlsso\RuleSamlCollection;
use GlpiPlugin\Samlsso\Controller\SamlSsoController;

global $CFG_GLPI;

/** PLUGIN CONSTANTS */
/** Plugin name */
define('PLUGIN_NAME', 'samlsso');
/** Plugin version */
define('PLUGIN_SAMLSSO_VERSION', '1.3.2');
/** Min required GLPI version */
define('PLUGIN_SAMLSSO_MIN_GLPI', '11.0.0');
/** Max GLPI compat version */
define('PLUGIN_SAMLSSO_MAX_GLPI', '12.99.99');
/** specifies log extention */
define('PLUGIN_SAMLSSO_LOGEVENTS', 'events');
/** Location of the main classes */
define('PLUGIN_SAMLSSO_SRCDIR', __DIR__ . '/src');
/**
 * Ordered list of fully-qualified class names for every plugin class that
 * implements a database lifecycle (install / uninstall).
 *
 * IMPORTANT: String literals are used intentionally instead of ::class constants.
 * This constant is defined at file-load time, before plugin_init_samlsso() has
 * had a chance to register the Composer autoloader. Using ::class would require
 * each class to be already loadable, which is NOT guaranteed when GLPI calls
 * this file while the plugin is in a disabled state (e.g. during uninstall).
 *
 * The order is significant: install() iterates forward (dependency order) and
 * uninstall() iterates in reverse (reverse dependency order), so child tables
 * that reference parent tables must appear after their parent in this list.
 */
define('PLUGIN_SAMLSSO_CLASSES', [
    /** Core IDP configuration table (parent) */
    'GlpiPlugin\\Samlsso\\Config',
    /** URL exclusion rules */
    'GlpiPlugin\\Samlsso\\Exclude',
    /** Session state tracking */
    'GlpiPlugin\\Samlsso\\LoginState',
    /** Claim-to-field mapping rules (references Config) */
    'GlpiPlugin\\Samlsso\\ClaimMap',
    /** Passively observed claim keys (references Config) */
    'GlpiPlugin\\Samlsso\\ObservedClaim',
    /** Cron task registration */
    'GlpiPlugin\\Samlsso\\CronTask',
]);

/**
 * Return the canonical plugin URL used by GLPI 11 and later, including marketplace installs.
 *
 * @return string Canonical plugin web directory with a trailing slash.
 */
function samlsso_plugin_web_dir(): string /** NOSONAR: GLPI API. */
{
    global $CFG_GLPI;
    return (string) ($CFG_GLPI['root_doc'] ?? '') . '/plugins/' . PLUGIN_NAME;
}

/**
 * Returns the absolute plugin web base URL, computed at call time.
 *
 * On GLPI >= 12, 'setup.php' may be included during the kernel boot phase
 * (PostBootListener 'BootPlugins'), which runs BEFORE the GLPI configuration
 * ('glpi_configs' values such as 'url_base') is loaded from the database.
 * The PLUGIN_SAMLSSO_WEBDIR constant is therefore evaluated with an empty
 * 'url_base' on GLPI 12 and produces relative URLs. Relative ACS/SLO URLs are
 * rejected by php-saml in strict mode ('sp_acs_url_invalid',
 * 'sp_sls_url_invalid') and copy/pasted IdP metadata URLs become unusable.
 *
 * This function must be preferred over the constant everywhere an absolute
 * URL is required (php-saml settings, metadata/ACS/SLO URLs exposed to the
 * administrator). Redirect targets tolerate relative URLs but use this
 * function as well for consistency.
 *
 * @return string Absolute base URL of the plugin, with a trailing slash.
 * @see https://github.com/DonutsNL/samlsso/issues/41
 */
function samlsso_webdir(): string /** NOSONAR: GLPI API. */
{
    global $CFG_GLPI;
    $urlBase = (isset($CFG_GLPI['url_base'])) ? rtrim((string) $CFG_GLPI['url_base'], '/') : '';
    return ($urlBase !== '' ? $urlBase . '/plugins/' . PLUGIN_NAME : samlsso_plugin_web_dir()) . '/';
}

/** METHODS */
/**
 * Default GLPI Plugin bootstrap function.
 * @return void
 * @see https://github.com/glpi-project/glpi/issues/21414
 */
function plugin_samlsso_boot(): void /** NOSONAR: GLPI API. */
{
    /** Register the assertion Service as stateless (prevent csrf checking) */
    SessionManager::RegisterPluginStatelessPath(PLUGIN_NAME, '#^/front/acs/#');
    /** Register the logout service as stateless (prevent csrf checking) */
    SessionManager::registerPluginStatelessPath(PLUGIN_NAME, '#^/front/slo/#');
}

/**
 * @return void
 * @see https://glpi-developer-documentation.readthedocs.io/en/master/plugins/requirements.html
 */
function plugin_init_samlsso(): void /** NOSONAR: GLPI API. */
{

    global $PLUGIN_HOOKS; /** NOSONAR: GLPI API. */
    $plugin = new Plugin();

    /** Include additional composer PSR4 autoloader */
    include_once __DIR__ . '/vendor/autoload.php';

    /** Backend block for local login when Enforced is enabled */
    $is_login_post = isset($_POST['login_name']) && isset($_POST['login_password']);

    /** Check if bypass flag exists in the whitelisted plugin session namespace */
    $is_bypassed = !empty($_SESSION['glpi_plugins']['samlsso']['bypass']);

    if ($is_login_post && !$is_bypassed && Session::getLoginUserID() === false && Config::getIsEnforced()) {
        /** Log the blocked login attempt to the plugin events log */
        Toolbox::logInFile(
            PLUGIN_NAME . PLUGIN_SAMLSSO_LOGEVENTS,
            sprintf("SSO enforcement blocked local login attempt for user: %s\n", $_POST['login_name'])
        );
        /** Nullify both username and password payloads to securely prevent native login */
        $_POST['login_name'] = null;
        $_POST['login_password'] = null;
    }

    /** Do not show config buttons if plugin is not enabled. */
    if ($plugin->isInstalled(PLUGIN_NAME) || $plugin->isActivated(PLUGIN_NAME)) {
        /** Hook the configuration page */
        if (Session::haveRight('config', UPDATE)) {
            $PLUGIN_HOOKS['config_page'][PLUGIN_NAME]       = SamlSsoController::CONFIG_ROUTE; /** NOSONAR: GLPI API. */
        }

        /** Add samlSSO configuration page to menu */
        $PLUGIN_HOOKS['menu_toadd'][PLUGIN_NAME]['config']  = [Config::class];

        /** Register CSS file for the plugin */
        $PLUGIN_HOOKS['add_css'][PLUGIN_NAME]               = ['css/samlSSO.css'];

        /** Register and hook the samlRules to Hooks::RULE_MATCHED */
        Plugin::registerClass(RuleSamlCollection::class, ['rulecollections_types' => true]);
        $PLUGIN_HOOKS[Hooks::RULE_MATCHED][PLUGIN_NAME]     = 'updateUser';

        /** Register and hook the loginFlow to Hooks::POST_INIT. */
        Plugin::registerClass(LoginFlow::class);
        $PLUGIN_HOOKS[Hooks::POST_INIT][PLUGIN_NAME]        = 'plugin_samlsso_evalAuth';

        /** Hook the login buttons to Hooks::DISPLAY_LOGIN */
        $PLUGIN_HOOKS[Hooks::DISPLAY_LOGIN][PLUGIN_NAME]    = 'plugin_samlsso_displaylogin';
    }
}

/**
 * Returns the name and the version of the plugin.
 *
 * @return array
 */
function plugin_version_samlsso(): array /** NOSONAR: GLPI API. */
{
    return [
        'name'           => 'samlsso',
        'oldname'        => 'glpisaml',
        'version'        => PLUGIN_SAMLSSO_VERSION,
        'author'         => 'Chris Gralike',
        'license'        => 'GPLv3',
        'homepage'       => 'https://github.com/DonutsNL/samlSSO/',
        'requirements'   => [
            'glpi' => [
                'min' => PLUGIN_SAMLSSO_MIN_GLPI,
                'max' => PLUGIN_SAMLSSO_MAX_GLPI,
            ],
            'php'    => [
                'min' => '8.0'
            ],
        ],
    ];
}

/**
 * Check pre-requisites before install.
 *
 * @return boolean
 */
function plugin_samlsso_check_prerequisites(): bool /** NOSONAR: GLPI API. */
{
    /** Make sure the external libs can be loaded */
    $autoloadPath = __DIR__ . '/vendor/autoload.php';
    if (!is_readable($autoloadPath) || !is_file($autoloadPath)) {
        echo 'Run composer install --no-dev in the plugin directory<br>';
        return false;
    }

    /** Test for simpleXML */
    if (!extension_loaded('simplexml')) {
        echo 'Please make sure php-xml is installed and loaded!<br>';
        return false;
    }

    /**
     * Add additional cookie validation because this is known to be faulty in many installations resulting in Session
     * Timeout issues recognisable by the &error=3 in the redirect URL. https://github.com/DonutsNL/samlsso/issues/13
     */
    if (
        ini_get('session.cookie_secure') == 1   ||
        ini_get('session.cookie_httponly') != 1 ||
        ini_get('session.cookie_samesite') == 0
    ) {
        echo "PHP is configured with the following Cookie settings.";
        echo "session.cookie_secure = " . ini_get('session.cookie_secure') . "<br>";
        echo "session.cookie_httponly = " . ini_get('session.cookie_httponly') . "<br>";
        echo "session.cookie_samesite =" . ini_get('session.cookie_samesite') . "<br>";
        /* phpcs:disable Generic.Files.LineLength.TooLong -- Preserve this multiline literal. */
        echo "These settings are <b>not aligned</b> with GLPI prerequisites. Please
              correct them as described <a href='https://glpi-install.readthedocs.io/en/latest/prerequisites.html#security-configuration-for-sessions'>
              in the GLPI Documentation</a>. SAML and GLPI redirects might not work correctly.";
        /* phpcs:enable Generic.Files.LineLength.TooLong */
    }

    return true;
}

/**
 * Check configuration process
 *
 * @param boolean $verbose Whether to display message on failure. Defaults to false
 * @return boolean
 */
function plugin_samlsso_check_config($verbose = false): bool /** NOSONAR: GLPI API. */
{
    if ($verbose) {
        echo __('Installed ', PLUGIN_NAME);
    }
    return true;
}
