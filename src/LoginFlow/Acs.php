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
 *  @since      1.0.0
 * ------------------------------------------------------------------------
 **/

declare(strict_types=1);

namespace GlpiPlugin\Samlsso\LoginFlow;

use Throwable;
use OneLogin\Saml2\Utils;
use OneLogin\Saml2\Settings;
use OneLogin\Saml2\Response;
use GlpiPlugin\Samlsso\LoginFlow;
use GlpiPlugin\Samlsso\LoginState;
use GlpiPlugin\Samlsso\Config\ConfigEntity;
use Symfony\Component\HttpFoundation\Request;

/**
 * Responsible to handle the incoming samlResponse. This object should
 * validate we are actually expecting an response and if we do validate it
 * If the response is valid, perform a callback to the loginFlow to handle
 * authentication, user creation and what not. Class is called by /front/acs.php
 *
 * This class is intended to be very unforgivable given its the vulnerable nature
 * of the samlResponse assertion while providing enough logging for the administrator
 * to figure out whats going on and how to resolve or prevent issues.
 *
 * Invoked by the AcsController
 */
class Acs extends LoginFlow
{
    private const UNSIGNED_ERROR = 'not signed';

    /** Define some error headers we use allot, not the best place but ok for now. */
    public const EXTENDED_HEADER = "================ BEGIN EXTENDED =================\n\n";
    public const EXTENDED_FOOTER = "================= END EXTENDED ==================\n\n";
    public const SERVER_OBJ      = "###############  ServerGlobal  ##################\n\n";
    public const STATE_OBJ       = "###############    StateObj    ##################\n\n";
    public const RESPONSE_OBJ    = "###############    Response    ##################\n\n";
    public const ERRORS          = "###############     Errors     ##################\n\n";

    /**
     * Stores the loginState object.
     * @since 1.0.0
     */
    protected ?LoginState $state = null;

    /**
     * Stores the debug param.
     * @since 1.0.0
     * @var bool
     */
    private $debug          = null;

    /**
     * Stores the idpId.
     * @since 1.2.0
     * @var int
     */
    private $idpId          = null;

    /**
     * Stores the samlResponse.
     * @since 1.2.0
     * @var Response
     */
    private $samlResponse   = null;

    /**
     * Stores the idp configuration.
     * @since 1.2.0
     * @var ConfigEntity
     */
    protected $configEntity = null;

    /**
     * Init pre fetches loginState or fails.
     *
     * @param Request $request Incoming HTTP request
     * @return void
     * @since 1.0.0
     */
    /**
     * Init pre fetches loginState or fails.
     *
     * @param Request $request Incoming HTTP request
     * @return void
     * @since 1.0.0
     */
    public function init(Request $request) /** NOSONAR: existing flow contract. */
    {
        /** Get post fields if any */
        $samlResponse = $request->get('SAMLResponse');
        $this->idpId = !empty($request->get(LoginState::IDP_ID)) ? (int) $request->get(LoginState::IDP_ID) : -1;

        if (!empty($samlResponse) && is_numeric($this->idpId)) {
            try {
                $this->configEntity = new ConfigEntity($this->idpId);
            } catch (Throwable) {
                $this->printError(
                    sprintf(__(
                        "Unable to fetch idp configuration with id: %s from database",
                        PLUGIN_NAME
                    ), $this->idpId),
                    __('Samlsso->acs->init->FetchConfig', PLUGIN_NAME)
                );
            }

            $this->debug = ($this->configEntity->getField(ConfigEntity::DEBUG)) ? true : false;

            $this->configureProxyVars();

            /**
             * Detect LogoutResponse (SLO return from IDP) and redirect silently.
             * Without this, the LogoutResponse is incorrectly processed as an AuthnResponse
             * causing Utils::getStatus() to throw "Missing Status on response".
             *
             * @see https://github.com/DonutsNL/samlsso/issues/138
             */
            $decoded = base64_decode($samlResponse);
            if (strpos($decoded, 'LogoutResponse') !== false) {
                \Html::redirect(samlsso_webdir() . \GlpiPlugin\Samlsso\Controller\SamlSsoController::SLO_ROUTE);
            }

            $this->setupSamlResponse($samlResponse);
            $this->fetchRequestState();

            /**
             * Everything is prepared for assertion! Perform assertion on the samlResponse
             */
            $this->assertSaml();
        } else {
            $this->printError(
                sprintf(__(
                    /* phpcs:ignore Generic.Files.LineLength.TooLong -- Preserve literal output and translation keys. */
                    'The received idp response did not contain the required samlResponse POST body or idpId to authenticate the user, see: %s for more information',
                    PLUGIN_NAME
                ), 'https://codeberg.org/QuinQuies/glpisaml/wiki/ACS.php'),
                __('Samlsso->acs->init->NoSamlResponse', PLUGIN_NAME),
                Acs::EXTENDED_HEADER .
                    Acs::SERVER_OBJ . var_export($_SERVER, true) . "\n\n" .
                    Acs::EXTENDED_FOOTER . "\n"
            );
        }
    }

    /**
     * Configure proxy variables for Utils if configured.
     *
     * @return void
     */
    private function configureProxyVars(): void
    {
        if ($this->configEntity->getField(ConfigEntity::PROXIED)) {
            try {
                $samltoolkit = new Utils();
                $samltoolkit::setProxyVars(true);
            } catch (Throwable $e) {
                $this->printError(
                    $e->getMessage(),
                    __('Samlsso->acs->init->phpsaml->Utils->setProxyVars', PLUGIN_NAME)
                );
            }
        }
    }

    /**
     * Set up the SAML response settings and response object.
     *
     * @param string $samlResponse The raw SAML Response string
     * @return void
     */
    private function setupSamlResponse(string $samlResponse): void
    {
        $samlSettings = null;
        try {
            $samlSettings = new Settings($this->configEntity->getPhpSamlConfig());
        } catch (Throwable $e) {
            $this->printError(
                __(
                    'PHP-SAML could not initialize the settings object using the configEntity.',
                    PLUGIN_NAME
                ) . $e->getMessage(),
                __('Samlsso->acs->init->phpsaml->initializeSettings', PLUGIN_NAME)
            );
        }

        try {
            /** Keep malformed assertion XML out of PHP diagnostics and restore the mode before an error page exits. */
            $previousXmlErrorMode = libxml_use_internal_errors(true);
            try {
                $this->samlResponse = new Response($samlSettings, $samlResponse);
            } finally {
                libxml_clear_errors();
                libxml_use_internal_errors($previousXmlErrorMode);
            }
        } catch (Throwable $e) {
            $this->printError(
                __(
                    'PHP-SAML library could not process samlResponse and reported the error:',
                    PLUGIN_NAME
                ) . $e->getMessage(),
                __('Samlsso->acs->init->phpsaml->initializeResponse', PLUGIN_NAME)
            );
        }
    }

    /**
     * Fetch the login request state from the database.
     *
     * @return void
     */
    private function fetchRequestState(): void
    {
        try {
            $inResponseTo = $this->samlResponse->getXMLDocument()->documentElement->getAttribute('InResponseTo');
            $this->state = new LoginState($inResponseTo);
            LoginFlow::$activeState = $this->state;
        } catch (Throwable $e) {
            /**
             * All references to state removed when state doesnt exist yet. Fix for:
             * https://github.com/DonutsNL/samlsso/issues/104
             */
            $this->printError(
                sprintf(__(
                    /* phpcs:ignore Generic.Files.LineLength.TooLong -- Preserve literal output and translation keys. */
                    "Could not fetch loginState from database with error: <br><br>%s<br><br>See: %s for more information.",
                    PLUGIN_NAME
                ), $e, 'https://codeberg.org/QuinQuies/glpisaml/wiki/LoginState.php'),
                __('Samlsso->acs->init->LoginState::construct', PLUGIN_NAME)
            );
        }
    }

    /**
     * This method asserts the provided samlResponse
     * and perform a callback to the loginFlow to authorize
     * the user if the samlResponse is valid.
     *
     * @return void
     * @since 1.0.0
     */
    public function assertSaml(): void
    {
        $this->validateSamlResponse();

        if ($this->state->getPhase() == LoginState::PHASE_TIMED_OUT) {
            $this->printError(
                __("Your SAML authentication request timed out. Please try logging in again.", PLUGIN_NAME),
                __('Samlsso->acs->assertSaml->Timeout', PLUGIN_NAME)
            );
        }

        /**
         * Prevent replay attacks, check if response_id is already used The response_id is unique and should only be
         * processed once. This is checked by comparing the response_id from the incoming samlResponse with the
         * response_id stored in the loginState. If the response_id is already set in the loginState, it means that the
         * samlResponse has already been processed and we are facing a replay attack. We also check if the state is in
         * the correct phase and that the response_id is not empty.
         */
        $currentResponseId = $this->samlResponse->getId();
        if (
            empty($currentResponseId) ||
            $this->state->getPhase() != LoginState::PHASE_SAML_ACS ||
            !empty($this->state->getSamlResponseId()) ||
            !$this->state->checkResponseIdUnique($currentResponseId)
        ) {
            $this->printError(
                sprintf(
                    /* phpcs:disable Generic.Files.LineLength.TooLong -- Preserve this multiline literal. */
                    __("It looks like this samlResponse has already been used to authenticate a different user.
                    Maybe an error occurred and you pressed F5 and accidently resend the samlResponse that is
                    already registered as processed. For security reasons we can not allow processed samlResponses
                    to be processed again. Please login again to generate a new samlResponse. Sorry for any inconvenience.
                    If the problem presists, then please contact your administrator.
                    See: %s for more information", PLUGIN_NAME),
                    /* phpcs:enable Generic.Files.LineLength.TooLong */
                    'https://codeberg.org/QuinQuies/glpisaml/wiki/LoginState.php'
                ),
                __('Samlsso->acs->assertSaml->LoginState::checkResponseIdUnique', PLUGIN_NAME),
                Acs::EXTENDED_HEADER .
                    /* phpcs:disable Generic.Files.LineLength.TooLong -- Preserve this multiline literal. */
                    "samlResponse with registered ID was replayed in acs.php. Possibly the user pressed F5 when encountering
                    a different error or the response was send successively to the acs\n\n" .
                    /* phpcs:enable Generic.Files.LineLength.TooLong */
                    Acs::SERVER_OBJ . var_export($_SERVER, true) . "\n\n" .
                    Acs::STATE_OBJ . var_export($this->state->getSafeStateForLogging($this->debug), true) . "\n\n" .
                    Acs::STATE_OBJ . var_export($this->samlResponse->getXMLDocument(), true) . "\n\n" .
                    Acs::EXTENDED_FOOTER . "\n"
            );
        } else {
            /**
             * The response is unique, register it in the database to prevent future replays of this document.
             */
            try {
                $this->state->setSamlResponseId($currentResponseId);

                /** Capture raw SAML response XML, anonymize it, and save its structure */
                $xml = $this->samlResponse->getXMLDocument()->saveXML();
                $anonymizedXml = ConfigEntity::anonymizeXml($xml);
                $this->configEntity->updateXmlStructure($anonymizedXml);
            } catch (Throwable $e) {
                $this->printError(
                    __(
                        /* phpcs:ignore Generic.Files.LineLength.TooLong -- Preserve literal output and translation keys. */
                        "An error occured while trying to update the samlResponseId into the LoginState database. Review the saml log for more details",
                        PLUGIN_NAME
                    ),
                    __('Samlsso->acs->assertSaml->LoginState::setSamlResponseId', PLUGIN_NAME),
                    "The following error was reported: $e"
                );
            }
        }

        /**
         * Only if the registered session is in phase PHASE_SAML_ACS (2) do we allow further processing. This check is
         * to prevent parallel requests or intentionally created race-conditions forcing the plugin into an
         * inconsistant state possibly allowing a session to forcefully being logged in.
         */
        if ($this->state->getPhase() != LoginState::PHASE_SAML_ACS) {
            /** Generate error and log state and response into the errorlog. */
            $this->printError(
                sprintf(
                    __("GLPI did not expect an assertion from this Idp. The most likely reason is a race condition
                    causing an inconsistant loginState in the database or software bug. Please login again via the
                    GLPI-interface. Sorry for the inconvenience. See: %s
                    for more information", PLUGIN_NAME),
                    'https://github.com/DonutsNL/samlsso/wiki/Unsollicited-%E2%80%90-IdP-initiated-login-flows'
                ),
                __('Samlsso->acs->assertSaml->PhaseMismatched', PLUGIN_NAME),
                Acs::EXTENDED_HEADER .
                    sprintf(
                        __(
                        /* phpcs:disable Generic.Files.LineLength.TooLong -- Preserve this multiline literal. */
                            "Unexpected assertion triggered while session was in a different phase then expected (2). This error was triggered by external source
                        with address:%s. Possible causes include race-conditions or parallel calls using the same samlResponse.\n",
                        /* phpcs:enable Generic.Files.LineLength.TooLong */
                            PLUGIN_NAME
                        ),
                        $_SERVER['REMOTE_ADDR']
                    ) .
                    Acs::STATE_OBJ . var_export($this->state->getSafeStateForLogging($this->debug), true) . "\n\n" .
                    Acs::EXTENDED_FOOTER . "\n"
            );
        }

        /**
         * Update the state to SAML AUTH, again to prevent raceconditions or parallel calls using the same samlResponse
         * to the acs.php. This first call should complete (if everything lines up).
         */
        try {
            $this->state->setPhase(LoginState::PHASE_SAML_AUTH);
        } catch (Throwable $e) {
            $this->printError(
                /* phpcs:disable Generic.Files.LineLength.TooLong -- Preserve this multiline literal. */
                __("An error occured while trying to update the login phase to LoginState::PHASE_SAML_AUTH  into the LoginState database.
                                  Review the saml log for more details", PLUGIN_NAME),
                /* phpcs:enable Generic.Files.LineLength.TooLong */
                __('LoginState', PLUGIN_NAME),
                "The following error was reported: $e"
            );
        }

        /** Perform validation check moved to top of method for security. */

        /**
         * Call the performGlpiLogin from the LoginFlow object We include the state because this session is still
         * stateless (from GLPIs perspective). and we cant trust the current sessionId to align because initial cookies
         * are tainted and prob not passed back to GLPI after the IDP redirect causing GLPI to reset the PHP sessionId.
         */
        $this->performGlpiLogin($this->samlResponse, $this->state);
    }
    /**
     * Validate signatures and request binding before any authentication-state mutation.
     *
     * @return void
     * @throws \UnexpectedValueException When validation fails and the test exception boundary is enabled.
     */
    private function validateSamlResponse(): void
    {
        /**
         * Perform validation by phpSaml library This MUST be the first thing we do to prevent DoS attacks where an
         * attacker triggers phase changes or response registrations without a valid signature. We pass the expected
         * RequestID to allow phpSaml to validate the InResponseTo attribute.
         * https://github.com/DonutsNL/samlsso/issues/104
         */
        try {
            if (!$this->samlResponse->isValid($this->state->getSamlRequestId())) {
                $errorStr = $this->samlResponse->getError(false) ?: '';
                $suggestion = self::validationSuggestion($errorStr);
                $this->printError(
                    __("Validation of the samlResponse document failed", PLUGIN_NAME),
                    __('Samlsso->acs->assertSaml->SamlResponse::isValid', PLUGIN_NAME),
                    $errorStr . $suggestion
                );
            }
        } catch (Throwable $e) {
            $errorMsg = $e->getMessage() ?: '';
            $suggestion = stripos($errorMsg, 'signature') !== false
                ? __(" (Suggestion: verify the Identity Provider Certificates configuration)", PLUGIN_NAME) : '';
            $this->printError(
                __("Validation of the samlResponse document failed with a critical error", PLUGIN_NAME),
                __('Samlsso->acs->assertSaml->SamlResponse::isValid', PLUGIN_NAME),
                $errorMsg . $suggestion
            );
        }
    }

    /**
     * Select diagnostic advice without changing the underlying validation outcome.
     *
     * @param string $error Toolkit diagnostic text used only to select corrective advice.
     * @return string Translated advice, or an empty string when no known condition matches.
     */
    private static function validationSuggestion(string $error): string
    {
        $suggestions = [
            [['not encrypted'], __(
                " (Suggestion: check 'Want Assertions Encrypted' under Inbound Security in the Security tab)",
                PLUGIN_NAME
            )],
            [[self::UNSIGNED_ERROR, 'Message'],
                 __(
                     " (Suggestion: check 'Want Messages Signed' under Inbound Security in the Security tab)",
                     PLUGIN_NAME
                 )],
            [[self::UNSIGNED_ERROR, 'assertion'],
                 __(
                     " (Suggestion: check 'Want Assertions Signed' under Inbound Security in the Security tab)",
                     PLUGIN_NAME
                 )],
            [[self::UNSIGNED_ERROR, 'NameID'],
                 __(
                     " (Suggestion: check 'Want NameID Signed' under Inbound Security in the Security tab)",
                     PLUGIN_NAME
                 )],
            [['signature'], __(" (Suggestion: verify the Identity Provider Certificates configuration)", PLUGIN_NAME)],
            [['InResponseTo'], __(
                " (Suggestion: check proxy settings or ensure request timeout has not expired)",
                PLUGIN_NAME
            )],
        ];
        foreach ($suggestions as [$terms, $suggestion]) {
            $matches = array_filter($terms, static fn(string $term): bool => stripos($error, $term) !== false);
            if (count($matches) === count($terms)) {
                return $suggestion;
            }
        }
        return '';
    }
}
