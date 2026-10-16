<?php

declare(strict_types=1);
/**
 * ------------------------------------------------------------------------
 * GLPISaml
 *
 * GLPISaml is heavily influenced by the initial work of Derrick Smith's
 * PhpSaml. This project's intent is to address some structural issues and
 * changes made by the gradual development of GLPI and provide a free, safe
 * and functional way of implementing SAML authentication in GLPI.
 *
 * Copyright (C) 2024 by Chris Gralike
 * ------------------------------------------------------------------------
 *
 * LICENSE
 *
 * This file is part of GLPISaml project.
 *
 * GLPISaml plugin is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * GLPISaml is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with GLPISaml. If not, see <http://www.gnu.org/licenses/> or
 * https://choosealicense.com/licenses/gpl-3.0/
 *
 * ------------------------------------------------------------------------
 *
 *  @package    GLPISaml
 *  @version    1.3.2
 *  @author     Chris Gralike
 *  @copyright  Copyright (c) 2024 by Chris Gralike
 *  @license    GPLv3+
 *  @see        https://github.com/DonutsNL/GLPISaml/readme.md
 *  @link       https://github.com/DonutsNL/GLPISaml
 *  @since      1.0.0
 * ------------------------------------------------------------------------
 *
 * We have a GLPI state and a SAML state. This class is intended to manage
 * and validate both states and their validity at all times. It should for
 * instance allow the the plugin to invalidate a session for what ever reason
 * and force a user to login again. It also allows future SIEM integration
 * to forcefully invalidate any active sessions.
 *
 **/

namespace GlpiPlugin\Samlsso\Utility;

/** Render stored diagnostic traces as HTML without interpreting identity values as markup. */
final class LoginTraceRenderer
{
    public static function render(string $serialized): string
    {
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

    private static function escape(string $value): string
    {
        return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    }

    private static function fieldLabel(string $key): string
    {
        $labels = self::fieldLabels();
        $ruleFields = ['department', 'company', 'employee_type', 'location', 'locale', 'manager'];
        $fallback = in_array($key, $ruleFields, true) ? 'rule_field: ' . $key : ucwords(str_replace('_', ' ', $key));
        return $labels[$key] ?? $fallback;
    }

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
