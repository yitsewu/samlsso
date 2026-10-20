<?php

/**
 * ------------------------------------------------------------------------
 * samlSSO
 *
 * samlSSO is heavily influenced by the initial work of Derrick Smith's
 * PhpSaml. This project's intent is to address some structural issues and
 * changes made by the gradual development of GLPI and provide a free, safe
 * and functional way of implementing SAML authentication in GLPI.
 *
 * Copyright (C) 2024 by Chris Gralike
 * ------------------------------------------------------------------------
 *
 * LICENSE
 *
 * This file is part of the samlSSO plugin for GLPI.
 *
 * samlSSO is free software: you can redistribute it and/or modify
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
 *  @see        https://github.com/DonutsNL/samlsso/readme.md
 *  @link       https://github.com/DonutsNL/samlsso
 *  @since      1.3.2
 * ------------------------------------------------------------------------
 */

declare(strict_types=1);

namespace GlpiPlugin\Samlsso\Utility;

/**
 * Render stored login diagnostics without interpreting identity values as HTML.
 *
 * This presentation helper does not alter authentication or session state.
 */
final class LoginTraceRenderer
{
    /**
     * Format serialized trace steps in their stored order.
     *
     * @param string $serialized Serialized array produced by the login-state trace writer.
     * @return string Escaped HTML, or an empty string if the decoded value is not an array.
     */
    public static function render(string $serialized): string
    {
        /** Diagnostic data must not instantiate objects while being decoded for display. */
        $steps = $serialized === '' ? [] : unserialize($serialized, ['allowed_classes' => false]);
        if (!is_array($steps)) {
            return '';
        }
        $labels = self::stepLabels();
        $html = '';
        $number = 1;
        foreach ($steps as $key => $value) {
            $label = self::escape($labels[$key] ?? (string) $key);
            $html .= "<strong>$number. $label</strong><br/>&nbsp;&nbsp;↳ " . self::renderValue($value) . '<br/>';
            $number++;
        }
        return $html;
    }

    /**
     * Expand JSON object or array fields while preserving ordinary values as text.
     *
     * @param mixed $value Stored trace value, optionally containing JSON field details.
     * @return string Escaped HTML for the value or its individual fields.
     */
    private static function renderValue(mixed $value): string
    {
        if (!is_string($value) || (!str_starts_with($value, '{') && !str_starts_with($value, '['))) {
            return self::escape(self::plainValue($value));
        }
        $fields = json_decode($value, true);
        if (!is_array($fields) || json_last_error() !== JSON_ERROR_NONE) {
            return self::escape($value);
        }
        $parts = [];
        foreach ($fields as $key => $fieldValue) {
            $label = self::escape(self::fieldLabel((string) $key));
            $parts[] = "<strong>$label:</strong> " . self::escape(self::plainValue($fieldValue));
        }
        return implode('<br/>&nbsp;&nbsp;↳ ', $parts);
    }

    /**
     * Flatten nested diagnostic values before applying HTML escaping.
     *
     * @param mixed $value A scalar, array, or unsupported stored value.
     * @return string Readable scalar text; unsupported values become an empty string.
     */
    private static function plainValue(mixed $value): string
    {
        if (is_array($value)) {
            return implode(', ', array_map(self::plainValue(...), $value));
        }
        if (is_bool($value)) {
            return $value ? 'Yes' : 'No';
        }
        return is_scalar($value) ? (string) $value : '';
    }

    /**
     * Encode text for insertion into the trace HTML.
     *
     * @param string $value Untrusted diagnostic text.
     * @return string HTML-escaped text with invalid UTF-8 replaced.
     */
    private static function escape(string $value): string
    {
        return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    }

    /**
     * Resolve a known field label or derive a readable label for an unknown key.
     *
     * @param string $key Stored diagnostic field name.
     * @return string Plain-text field label, escaped by the caller.
     */
    private static function fieldLabel(string $key): string
    {
        $labels = self::fieldLabels();
        $ruleFields = ['department', 'company', 'employee_type', 'location', 'locale', 'manager'];
        $fallback = in_array($key, $ruleFields, true) ? 'rule_field: ' . $key : ucwords(str_replace('_', ' ', $key));
        return $labels[$key] ?? $fallback;
    }

    /**
     * Provide display names for the login steps recorded by the state machine.
     *
     * @return array<string, string> Stored step keys mapped to plain-text labels.
     */
    private static function stepLabels(): array
    {
        return [
            'rulesEngineInput'            => 'Rules Engine Input',
            'rulesEngineOutput'           => 'Rules Engine Output',
            'syncNoChanges'               => 'Synchronization Check',
            'syncUpdatedFields'           => 'Updated Fields',
            'finalIdp'                    => 'Identity Provider Selected',
            'OnlyOneIdpEnforced'          => 'Only One IDP Enforced',
            'bypassUsed'                  => 'SSO Bypass Utilized',
            'loginViaUserfield'           => 'Login Via User Field',
            'loginViaGetter'              => 'Login Via Query Parameter',
            'logoutPressed'               => 'Logout Action Initiated',
            'JIT group assigned'          => 'JIT Group Assigned',
            'JIT group assignment failed' => 'JIT Group Assignment Failed',
            'JIT profile assigned'        => 'JIT Profile Assigned',
            'JIT profile assignment failed' => 'JIT Profile Assignment Failed',
            'staleTimeout'                => __('ACS Timeout', PLUGIN_NAME),
        ];
    }

    /**
     * Provide display names for user fields and rule-engine results.
     *
     * @return array<string, string> Stored field keys mapped to plain-text labels.
     */
    private static function fieldLabels(): array
    {
        return [
            'name'                 => 'user_field: username',
            '_useremails'          => 'user_field: email',
            'realname'             => 'user_field: realname',
            'firstname'            => 'user_field: firstname',
            'phone'                => 'user_field: phone',
            'mobile'               => 'user_field: mobile',
            'samlClaimedJobTitle'  => 'user_field: jobtitle',
            'samlClaimedCountry'   => 'user_field: country',
            'samlClaimedCity'      => 'user_field: city',
            'samlClaimedStreet'    => 'user_field: street',
            'samlClaimedGroups'    => 'rule_field: groups',
            'groups'               => 'rule_field: groups',
            'email'                => 'rule_field: email',
            'jobtitle'             => 'rule_field: jobtitle',
            'country'              => 'rule_field: country',
            'city'                 => 'rule_field: city',
            'street'               => 'rule_field: street',
            'users_id'             => 'User ID',
            '_rule_process'        => 'Rule Processed',
            'specific_groups_id'   => 'Assigned Group ID',
            'profiles_id'          => 'Assigned Profile ID',
            'entities_id'          => 'Assigned Entity ID',
            'is_recursive'         => 'Recursive Profile Assignment',
            '_profiles_id_default' => 'Default Profile ID',
            '_entities_id_default' => 'Default Entity ID',
        ];
    }
}
