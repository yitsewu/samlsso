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

/**
 * Validate, evaluate, clean, normalizes, enriches, saml config items before
 * assigning them to the configEntity or invalidates the passed value with an
 * understandable translatable errormessage.
 */

class LoginFlowItem /** NOSONAR: persisted field API. */
{
    /** Name of the database field */
    public const FIELD      = 'field';
    /** Database type */
    public const TYPE       = 'datatype';
    /** NOT NULL setting */
    public const NULL       = 'notnull';
    /** Database value */
    public const VALUE      = 'value';
    /** Is content valid? */
    public const VALID      = 'valid';
    /** Is content invalid? */
    public const INVALID    = 'invalid';
    /** Rich values (like date object) */
    public const RICHVALUE  = 'richvalue';
    /** Evaluated properties */
    public const EVAL       = 'eval';
    /** Encountered problems notnull will prevent DB update/inserts */
    public const ERRORS     = 'errors';
    /** Could either be string or array */
    public const VALIDATE   = 'validate';
    /** What class constant is used for item */
    public const CONSTANT   = 'itemconstant';
    /** Field explanation */
    public const FORMEXPLAIN = 'formexplain';
    /** Form title to use with field */
    public const FORMTITLE  = 'formtitle';
    /** What validator was used */
    public const VALIDATOR  = 'validator';

    /**
     * Evaluate the noMethod configuration value.
     *
     * @param string $field Unknown configuration field name.
     * @param mixed $value Original field value.
     * @return array Invalid-field metadata explaining the unsupported field.
     */
    protected function noMethod(string $field, mixed $value): array
    {
        return [
            LoginFlowItem::FORMEXPLAIN => LoginFlowItem::INVALID,
            LoginFlowItem::VALUE     => $value,
            LoginFlowItem::FIELD     => $field,
            LoginFlowItem::VALIDATOR => __method__,
            LoginFlowItem::EVAL      => false,
            LoginFlowItem::ERRORS    => sprintf(__(
                "⭕ Undefined or no type validation found in ConfigValidate for item: %s",
                PLUGIN_NAME
            ), $field)
        ];
    }

    /**
     * Evaluate the id field for the configuration form.
     *
     * @param mixed $var Submitted or stored field value.
     * @return array Normalized value, validation result, and form metadata.
     */
    protected function id(mixed $var): array
    {
        /** Do some validation */
        $error = false;
        if (
            $var               &&
            $var != -1        &&
            !is_numeric($var)
        ) {
            $error = __('⭕ ID must be a positive numeric value!', PLUGIN_NAME);
        }

        return [
            LoginFlowItem::FORMEXPLAIN => __('Unique identifier for this configuration', PLUGIN_NAME),
            LoginFlowItem::FORMTITLE => __('CONFIG ID', PLUGIN_NAME),
            LoginFlowItem::EVAL      => ($error) ? LoginFlowItem::INVALID : LoginFlowItem::VALID,
            LoginFlowItem::VALUE     => (int) $var,
            LoginFlowItem::FIELD     => __function__,
            LoginFlowItem::VALIDATOR => __method__,
            LoginFlowItem::ERRORS    => ($error) ? $error : null,
        ];
    }

    /**
     * Evaluate the forcedIdp field for the configuration form.
     *
     * @param mixed $var Submitted or stored field value.
     * @return array Normalized value, validation result, and form metadata.
     */
    protected function forcedIdp(mixed $var): array
    {
        /** Do some validation */
        $error = false;
        if (
            $var               &&
            $var != -1        &&
            !is_numeric($var)
        ) {
            $error = __('⭕ IDP ID must be a positive numeric value!', PLUGIN_NAME);
        }

        return [
            LoginFlowItem::FORMEXPLAIN => __('What IDP ID should be enforced?', PLUGIN_NAME),
            LoginFlowItem::FORMTITLE => __('ENFORCED IDP ID', PLUGIN_NAME),
            LoginFlowItem::EVAL      => ($error) ? LoginFlowItem::INVALID : LoginFlowItem::VALID,
            LoginFlowItem::VALUE     => (int) $var,
            LoginFlowItem::FIELD     => __function__,
            LoginFlowItem::VALIDATOR => __method__,
            LoginFlowItem::ERRORS    => ($error) ? $error : null,
        ];
    }

    /**
     * Evaluate the debug field for the configuration form.
     *
     * @param mixed $var Submitted or stored field value.
     * @return array Normalized value, validation result, and form metadata.
     */
    protected function debug(mixed $var): array
    {
        if (empty($var)) {
            $var = '0';
        }

        return array_merge(
            [
                LoginFlowItem::FORMEXPLAIN   => __('Debug enabled?', PLUGIN_NAME),
                LoginFlowItem::FORMTITLE     => __('DEBUG', PLUGIN_NAME),
                LoginFlowItem::FIELD         => __function__,
                LoginFlowItem::VALIDATOR     => __method__,
            ],
            LoginFlowItem::handleAsBool($var, LoginFlowEntity::DEBUG)
        );
    }

    /**
     * Evaluate the enforced field for the configuration form.
     *
     * @param mixed $var Submitted or stored field value.
     * @return array Normalized value, validation result, and form metadata.
     */
    protected function enforced(mixed $var): array
    {
        if (empty($var)) {
            $var = '0';
        }

        return array_merge(
            [
                LoginFlowItem::FORMEXPLAIN   => __(
                    'Should SAML SSO be enforced. This option can be bypassed by the bypass var and value',
                    PLUGIN_NAME
                ),
                LoginFlowItem::FORMTITLE     => __('ENFORCE SSO', PLUGIN_NAME),
                LoginFlowItem::FIELD         => __function__,
                LoginFlowItem::VALIDATOR     => __method__,
            ],
            LoginFlowItem::handleAsBool($var, LoginFlowEntity::ENFORCED)
        );
    }

    /**
     * Evaluate the enableDomainLogin field for the configuration form.
     *
     * @param mixed $var Submitted or stored field value.
     * @return array Normalized value, validation result, and form metadata.
     */
    protected function enableDomainLogin(mixed $var): array
    {
        if (empty($var)) {
            $var = '0';
        }

        return array_merge(
            [
                LoginFlowItem::FORMEXPLAIN   => __('Try to match domain in username for IDP selection', PLUGIN_NAME),
                LoginFlowItem::FORMTITLE     => __('ENABLE DOMAIN BASED SSO', PLUGIN_NAME),
                LoginFlowItem::FIELD         => __function__,
                LoginFlowItem::VALIDATOR     => __method__,
            ],
            LoginFlowItem::handleAsBool($var, LoginFlowEntity::ENABLEDOMAIN)
        );
    }

    /**
     * Evaluate the enableGetterLogin field for the configuration form.
     *
     * @param mixed $var Submitted or stored field value.
     * @return array Normalized value, validation result, and form metadata.
     */
    protected function enableGetterLogin(mixed $var): array
    {
        if (empty($var)) {
            $var = '0';
        }

        return array_merge(
            [
                LoginFlowItem::FORMEXPLAIN   => __(
                    'Allow the ?idpId=[val] URI to pre select IDP from URLs',
                    PLUGIN_NAME
                ),
                LoginFlowItem::FORMTITLE     => __('Enable getter login', PLUGIN_NAME),
                LoginFlowItem::FIELD         => __function__,
                LoginFlowItem::VALIDATOR     => __method__,
            ],
            LoginFlowItem::handleAsBool($var, LoginFlowEntity::ENABLEIDPGETTER)
        );
    }

    /**
     * Evaluate the hideGlpiLogin field for the configuration form.
     *
     * @param mixed $var Submitted or stored field value.
     * @return array Normalized value, validation result, and form metadata.
     */
    protected function hideGlpiLogin(mixed $var): array
    {
        if (empty($var)) {
            $var = '0';
        }

        return array_merge(
            [
                LoginFlowItem::FORMEXPLAIN   => __(
                    'Hide the default GLPI login options. This option can be bypassed using the bypass var and value.',
                    PLUGIN_NAME
                ),
                LoginFlowItem::FORMTITLE     => __('HIDE GLPI LOGIN', PLUGIN_NAME),
                LoginFlowItem::FIELD         => __function__,
                LoginFlowItem::VALIDATOR     => __method__,
            ],
            LoginFlowItem::handleAsBool($var, LoginFlowEntity::HIDEGLPILOGIN)
        );
    }

    /**
     * Evaluate the hideSamlButtons field for the configuration form.
     *
     * @param mixed $var Submitted or stored field value.
     * @return array Normalized value, validation result, and form metadata.
     */
    protected function hideSamlButtons(mixed $var): array
    {
        if (empty($var)) {
            $var = '0';
        }

        return array_merge(
            [
                LoginFlowItem::FORMEXPLAIN   => __(
                    'Hides Saml Buttons. This option cannot be used together with the Hide GLPI login.',
                    PLUGIN_NAME
                ),
                LoginFlowItem::FORMTITLE     => __('Hide Saml Buttons', PLUGIN_NAME),
                LoginFlowItem::FIELD         => __function__,
                LoginFlowItem::VALIDATOR     => __method__,
            ],
            LoginFlowItem::handleAsBool($var, LoginFlowEntity::HIDEBUTTONS)
        );
    }

    /**
     * Evaluate the hidePassword field for the configuration form.
     *
     * @param mixed $var Submitted or stored field value.
     * @return array Normalized value, validation result, and form metadata.
     */
    protected function hidePassword(mixed $var): array
    {
        if (empty($var)) {
            $var = '0';
        }

        return array_merge(
            [
                LoginFlowItem::FORMEXPLAIN   => __(
                    'Hide the GLPI password field. To be used with Enable Domain Login.',
                    PLUGIN_NAME
                ),
                LoginFlowItem::FORMTITLE     => __('HIDE PASSWORD FIELD', PLUGIN_NAME),
                LoginFlowItem::FIELD         => __function__,
                LoginFlowItem::VALIDATOR     => __method__,
            ],
            LoginFlowItem::handleAsBool($var, LoginFlowEntity::HIDEPASSWORD)
        );
    }

    /**
     * Evaluate the reApplyRulesOnAuth field for the configuration form.
     *
     * @param mixed $var Submitted or stored field value.
     * @return array Normalized value, validation result, and form metadata.
     */
    protected function reApplyRulesOnAuth(mixed $var): array
    {
        if (empty($var)) {
            $var = '0';
        }

        return array_merge(
            [
                LoginFlowItem::FORMEXPLAIN   => __(
                    'Forces samlSSO to (re)apply the rules on each successful auth.',
                    PLUGIN_NAME
                ),
                LoginFlowItem::FORMTITLE     => __('APPLY RULES ON AUTH', PLUGIN_NAME),
                LoginFlowItem::FIELD         => __function__,
                LoginFlowItem::VALIDATOR     => __method__,
            ],
            LoginFlowItem::handleAsBool($var, LoginFlowEntity::RULESONAUTH)
        );
    }

    /**
     * Make sure we always return the correct boolean datatype.
     *
     * @param mixed $var Submitted boolean-like field value.
     * @param string|null $field Field label used in validation messages.
     * @return array Validation result, normalized value, and any error message.
     */
    protected function handleAsBool(mixed $var, $field = null): array
    {
        /** Default to false if no or an impropriate value is provided. */
        $error = (!empty($var) && !preg_match('/[0-1]/', (string) $var)) ? sprintf(__(
            "⭕ %s can only be 1 or 0",
            PLUGIN_NAME
        ), $field) : null;

        /**
         * Value is intentionally typed as string is it might be shown as a value in the form fields, The return value
         * should be casted to the correct type in receiving methods if so required.
         */
        return [
            LoginFlowItem::EVAL   => (is_numeric($var)) ? LoginFlowItem::VALID : LoginFlowItem::INVALID,
            LoginFlowItem::VALUE  => (!$error) ? "$var" : '0',
            LoginFlowItem::ERRORS => $error
        ];
    }
}
