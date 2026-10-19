<?php

/**
 * samlSSO rule-page integration contract tests.
 *
 * Copyright (C) 2024 by Chris Gralike
 *
 * This file is part of samlSSO plugin for GLPI.
 *
 * samlSSO is free software: you can redistribute it and/or modify it under the
 * terms of the GNU Affero General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option)
 * any later version.
 *
 * samlSSO is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License for
 * more details. You should have received a copy of the GNU Affero General
 * Public License along with samlSSO. If not, see <https://www.gnu.org/licenses/>.
 *
 * @package samlSSO
 * @version 1.3.2
 * @license AGPL-3.0-or-later
 */

declare(strict_types=1);

/** Standalone tests declare core doubles and execute assertions in the same isolated PHP process. */
// phpcs:disable PSR1.Files.SideEffects.FoundWithSymbols
/** These two doubles must retain GLPI's global class names for the actual plugin code to resolve them. */
// phpcs:disable PSR1.Classes.ClassDeclaration.MissingNamespace, PSR1.Classes.ClassDeclaration.MultipleClasses

/** Record the permission guard before either included core page is reached. */
class Session
{
    public static bool $allowed = false;
    public static int $checks = 0;

    /**
     * Check the exact right required by the SAML rule-management entry points.
     *
     * @param string $right Requested GLPI right.
     * @param int $level Requested permission level.
     * @return void
     * @throws DomainException When the fixture user has no rule-management access.
     * @throws UnexpectedValueException When the entry point checks the wrong permission.
     */
    public static function checkRight(string $right, int $level): void
    {
        self::$checks++;
        if ($right !== 'rule_import' || $level !== READ) {
            throw new UnexpectedValueException('Unexpected rule-management permission.');
        }
        if (!self::$allowed) {
            throw new DomainException('Rule-management access denied.');
        }
    }
}

/** Provide only the core collection operations used by the two included pages. */
class RuleCollection
{
    public static int $checks = 0;
    public static int $listDisplays = 0;
    public static int $ruleLoads = 0;

    /**
     * Verify that the included core page received the actual plugin collection.
     *
     * @param int $level Requested permission level.
     * @return void
     * @throws UnexpectedValueException When a different collection or permission is supplied.
     */
    public function checkGlobal(int $level): void
    {
        if (!$this instanceof GlpiPlugin\Samlsso\RuleSamlCollection || $level !== READ) {
            throw new UnexpectedValueException('Core page did not receive the SAML rule collection.');
        }
        self::$checks++;
    }

    /**
     * Record the list rendering requested by the core fixture.
     *
     * @param array<string, bool> $options List options provided by the core page.
     * @return void
     * @throws UnexpectedValueException When criteria or actions are missing from the list.
     */
    public function display(array $options): void
    {
        if ($options !== ['display_criterias' => true, 'display_actions' => true]) {
            throw new UnexpectedValueException('Rule list display options changed.');
        }
        self::$listDisplays++;
    }

    /**
     * Return the actual rule object used by the form entry point.
     *
     * @return GlpiPlugin\Samlsso\RuleSaml The plugin rule instance.
     */
    public function getRuleClass(): GlpiPlugin\Samlsso\RuleSaml
    {
        self::$ruleLoads++;
        return new GlpiPlugin\Samlsso\RuleSaml();
    }
}

// phpcs:enable PSR1.Classes.ClassDeclaration.MissingNamespace, PSR1.Classes.ClassDeclaration.MultipleClasses

/**
 * These fixtures preserve the local-variable contract of GLPI 11.0.11 and 12.0.0:
 * front/rule.common.php and front/rule.common.form.php both consume $rulecollection.
 * Temporary files let the real plugin methods exercise PHP's include scope.
 */
$fixtureRoot = sys_get_temp_dir() . '/samlsso-rule-pages-' . bin2hex(random_bytes(8));
if (!mkdir($fixtureRoot . '/front', 0700, true)) {
    throw new UnexpectedValueException('Could not create the rule-page fixture directory.');
}
$listPath = $fixtureRoot . '/front/rule.common.php';
$formPath = $fixtureRoot . '/front/rule.common.form.php';
$exitCode = 0;

try {
    define('READ', 1);
    define('GLPI_VERSION', '11.0.11');
    define('GLPI_ROOT', $fixtureRoot);
    require_once __DIR__ . '/Shims.php';
    require_once __DIR__ . '/../src/RuleSaml.php';
    require_once __DIR__ . '/../src/RuleSamlCollection.php';

    $listFixture = <<<'PHP'
<?php
$rulecollection->checkGlobal(READ);
$rulecollection->display(['display_criterias' => true, 'display_actions' => true]);
PHP;
    $formFixture = <<<'PHP'
<?php
$rule = $rulecollection->getRuleClass();
$rulecollection->checkGlobal(READ);
if (!$rule instanceof \GlpiPlugin\Samlsso\RuleSaml) {
    throw new \UnexpectedValueException('Rule form received the wrong rule class.');
}
PHP;
    if (
        file_put_contents($listPath, $listFixture) === false
        || file_put_contents($formPath, $formFixture) === false
    ) {
        throw new UnexpectedValueException('Could not write the rule-page fixtures.');
    }

    $rule = new GlpiPlugin\Samlsso\RuleSaml();
    foreach (['invoke', 'invokeForm'] as $entryPoint) {
        try {
            $rule->$entryPoint();
            throw new UnexpectedValueException('Rule-management permission guard was bypassed.');
        } catch (DomainException) {
            /** The denied attempt must not execute either included page. */
        }
    }
    if (RuleCollection::$checks !== 0 || RuleCollection::$ruleLoads !== 0) {
        throw new UnexpectedValueException('Denied access reached a core rule page.');
    }

    Session::$allowed = true;
    $rule->invoke();
    $rule->invokeForm();
    if (
        Session::$checks !== 4 || RuleCollection::$checks !== 2
        || RuleCollection::$listDisplays !== 1 || RuleCollection::$ruleLoads !== 1
    ) {
        throw new UnexpectedValueException('The list and form include contracts were not both exercised.');
    }
    echo "✅ Rule list and form receive their collection through the real include scope\n";
    echo "✅ Rule-management permission guards run before either included page\n";
} catch (Throwable $error) {
    echo '❌ Rule-page contract failed: ' . $error->getMessage() . "\n";
    $exitCode = 1;
} finally {
    foreach ([$listPath, $formPath] as $fixturePath) {
        if (is_file($fixturePath)) {
            unlink($fixturePath);
        }
    }
    rmdir($fixtureRoot . '/front');
    rmdir($fixtureRoot);
}

if ($exitCode !== 0) {
    exit($exitCode);
}
