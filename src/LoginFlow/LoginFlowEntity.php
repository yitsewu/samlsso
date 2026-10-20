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

use ReflectionClass;
use GlpiPlugin\Samlsso\Config as SamlConfig;
use GlpiPlugin\Samlsso\Config\ConfigItem;

/**
 * Class ConfigEntity's job is to populate, evaluate, test, normalize and
 * make sure we always return a consistent, valid, and usable instance of
 * a samlConfiguration thats either based on a template or based on an
 * existing database row
 */

class LoginFlowEntity extends LoginFlowItem
{
    /**
     * Be aware, this class is being reflected, so dont store 'private' constants in this class as they will be
     * included in the reflection!
     */
    /** Database ID */
    public const ID              = 'id';
    /** Enable debugging */
    public const DEBUG           = 'debug';
    /** Enable enforced SSO */
    public const ENFORCED        = 'enforced';
    /** Enforce specific IDP configuration */
    public const ENFORCEDIDP     = 'forcedIdp';
    /** Enable domain based Login using domain in username */
    public const ENABLEDOMAIN    = 'enableDomainLogin';
    /** Enable getter based Login remote SP initiated login */
    public const ENABLEIDPGETTER = 'enableGetterLogin';
    /** hide default Glpi Login fields */
    public const HIDEGLPILOGIN   = 'hideGlpiLogin';
    /** hide Saml Buttons */
    public const HIDEBUTTONS     = 'hideSamlButtons';
    /** hide GLPI PasswordField */
    public const HIDEPASSWORD    = 'hidePassword';
    /** (re)Apply rules on each succesfull auth */
    public const RULESONAUTH     = 'applyRulesOnAuth';
    /** Apply rules on JIT */
    public const RULESONJIT      = 'applyRulesOnJit';
    /** Allow unsolicited responses */
    public const ALLOWUNSOLICITED = 'allowUnsolicited';
    /** Store and process redirects */
    public const ENABLEREDIRECT  = 'processRedirects';
    /** What value to verify to allow enforced bypass */
    public const BYPASSSTR       = 'byPassString';
    /** What property to use for {bypass var}={bypass string} */
    public const BYPASSVAR       = 'byPassVar';
    /** Also log user out with IDP if user logs out of GLPI */
    public const ENABLEIDPLOGOUT = 'enableIdpLogout';
    /** Always perform 'reauth' after designated timeout period */
    public const ENFORCEIDLE     = 'enforceReAuthAfterIdle';
    /** future use, not sure yet how to best implement this. */
    public const BLOCKLOGIN      = 'blockAfterEnfocedLogout';
    public const IS_DELETED      = 'is_deleted';
    public const CREATE_DATE     = 'date_creation';
    public const MOD_DATE        = 'date_mod';

    /**
     * True, if an configuration issue is found its set to false.
     */
    private $isValid            = true;

    /**
     * Contains all field values of a certain configuration
     */
    private $fields             = [];

    /**
     * Contains all validation error messages generated during validation
     */
    private $invalidMessages    = [];

    /**
     * The LoginFlowEntity class constructor
     *
     * @param int $id Login flow configuration identifier.
     * @param array $options Template selection and optional submitted form data.
     * @throws \InvalidArgumentException When submitted postData is not an array.
     */
    public function __construct(int $id = 1, array $options = [])
    {
        if (($options['template'] ?? '') === 'post') {
            /** Validate only declared form fields; do not silently discard submitted values. */
            $postData = $options['postData'] ?? [];
            if (!is_array($postData)) {
                throw new \InvalidArgumentException('Login flow postData must be an array');
            }
            foreach ($postData as $field => $value) {
                if (in_array($field, self::getConstants(), true)) {
                    $this->evaluateItem($field, $value);
                }
            }
        } else {
            $this->validateAndPopulateDBEntity($id);
        }
    }

    /**
     * Populates the instance of ConfigEntity using a DB query from the LoginFlow table.
     *
     * @param  int      $id             - id of the database row to fetch
     * @return void
     */
    private function validateAndPopulateDBEntity($id): void
    {
        /** Get configuration from database; */
        $config = new SamlConfig();
        if ($config->getFromDB($id)) {
            /** Iterate through fetched fields */
            foreach ($config->fields as $field => $value) {
                /**
                 * Do validations on all provided fields. All fields need to be verified by
                 * GlpiPlugin\Glpisaml\Config\ConfigItem per default.
                 */
                $this->evaluateItem((string) $field, $value);
            }
        }
    }

    /**
     * Validates and normalizes configuration fields using checks defined
     * in class GlpiPlugin\Glpisaml\Config\ConfigItem. For instance
     * if defined in ConfigItem, it will convert DB result (string) '1'
     * too (boolean) true in the returned array for type safety purposes.
     *
     * @param  string   $field       - name of the field to validate
     * @param  mixed    $value       - value belonging to the field.
     * @param  bool     $invalidate  - whether to invalidate value on failure
     * @return array                 - result of the validation including normalized values.
     * @see https://www.mysqltutorial.org/mysql-basics/mysql-boolean/
     */
    private function evaluateItem(string $field, mixed $value, $invalidate = false): array
    {
        /** Verify we have a method to evaluate the given field. */
        $evaluatedItem = (method_exists(
            get_parent_class($this),
            $field
        )) ? $this->$field($value) : $this->noMethod($field, $value);

        if (
            isset($evaluatedItem[ConfigItem::EVAL])      &&
            $evaluatedItem[ConfigItem::EVAL] == 'valid'
        ) {
            $this->fields[$field] = $evaluatedItem[ConfigItem::VALUE];
        } else {
            /** Pass or invalidate */
            $this->fields[$field] = ($invalidate) ? '' : $value;
            /** Add errormessage */
            $this->invalidMessages[$field] = (isset($evaluatedItem[ConfigItem::ERRORS]))
                ? $evaluatedItem[ConfigItem::ERRORS]
                : 'UNDEFINED';
            /** Mark entity invalid */
            $this->isValid = false;
        }
        return $evaluatedItem;
    }

    /**
     * This static function will return the configuration constants
     * defined in this class. Idea is to use this reflection to
     * validate the database fields names, numbers and so forth to detect
     * update caused DB issues.
     *
     * @return array            - defined ConfigEntity class constants.
     * @see https://www.php.net/manual/en/reflectionclass.getconstants.php
     */
    public static function getConstants(): array
    {
        $reflectedObj = new ReflectionClass(__CLASS__);
        return $reflectedObj->getConstants(); /** NOSONAR: public constants only. */
    }

    /**
     * This function will return contextual and actual information about the handled
     * configuration fields. It will also perform advanced validations and correct
     * invalid configuration options before save in database.
     *
     * Intended for generating Config->searchOptions, ConfigForm->showForm().
     *
     * @return array            - ConfigEntity field information
     */
    public function getFields(): array /** NOSONAR: existing flow contract. */
    {
        global $DB;
        $fields = [];
        /** Fetch config item constants; */
        $classConstants = LoginFlowEntity::getConstants();
        /** Fetch database columns; */
        $sql = 'SHOW COLUMNS FROM ' . SamlConfig::getTable();
        $result = $DB->doQuery($sql);
        if ($result) {
            for ($data = $result->fetch_assoc(); $data; $data = $result->fetch_assoc()) {
                $key = array_search($data['Field'], $classConstants);
                $fields[$data['Field']] = [
                    ConfigItem::FIELD       => $data['Field'],
                    ConfigItem::TYPE        => $data['Type'],
                    ConfigItem::NULL        => $data['Null'],
                    ConfigItem::CONSTANT    => $key ? "ConfigEntity::$key" : 'UNDEFINED',
                    ConfigItem::VALUE       => (isset($this->fields[$data['Field']]))
                        ? $this->fields[$data['Field']]
                        : null,

                ];
                /** Evaluate and merge results. */
                $fields[$data['Field']] = array_merge(
                    $fields[$data['Field']],
                    $this->evaluateItem(
                        $data['Field'],
                        (isset($this->fields[$data['Field']])) ? $this->fields[$data['Field']] : ''
                    )
                );
            }
        }
        /** Validate spcert and key if provided */
        $fields = $this->validateAdvancedConfig($fields);
        return $fields;
    }

    /**
     * Returns the validated and normalized fields in the ConfigEntity
     * for database insertion. It will not add fields added to the
     * ignoreFields param.
     *
     * @param  array $ignoreFields fields to skip
     * @return array $fields with validated and corrected configuration
     */
    public function getDBFields($ignoreFields = []): array
    {
        $fields = [];
        foreach ($this->getFields() as $key => $value) {
            if (is_array($ignoreFields) && !in_array($key, $ignoreFields)) {
                $fields[$key] = $value[ConfigItem::VALUE];
            }
        }
        return $fields;
    }

    /**
     * Validate advanced configuration options and correct params if not supported by provided setup.
     *
     * @param  array $fields from getFields()
     * @return array $fields with corrected configuration options
     */
    private function validateAdvancedConfig(array $fields): array
    {
        /**
         * Allows for additional manipulation of configuration fields before passing them back to the form, for
         * instance illegal combinations of configuration options or cross object validations
         */
        return $fields;
    }

    /**
     * This function will return specific config field if it exists
     *
     * @param  string   $fieldName  - Name of the configuration item we are looking for, use class constants.
     * @return string|bool          - Value of the configuration or (bool) false if not found.
     */
    public function getField(string $fieldName): string|bool
    {
        if (
            key_exists($fieldName, $this->fields) &&
            is_int($this->fields[$fieldName])
        ) {
            return (bool) $this->fields[$fieldName];
        } elseif (key_exists($fieldName, $this->fields)) {
            return (string) $this->fields[$fieldName];
        } else {
            return false;
        }
    }

    /**
     * This function will return all registered error messages
     *
     * @return array           - List of registered error messages.
     */
    public function getErrorMessages(): array
    {
        return (count($this->invalidMessages) > 0) ? $this->invalidMessages : [];
    }

    /**
     * Returns the validity state of the currently loaded ConfigEntity
     * @return bool
     */
    public function isValid(): bool
    {
        return (bool) $this->isValid;
    }
}
