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

/**
 * RunAllTests.php
 *
 * Central test runner that executes all test suites in isolated processes.
 * Ensures each test file runs in its own process space to prevent shim/class definition conflicts.
 */

/**
 * Get the current test directory.
 */
$testDir = __DIR__;

/**
 * Find all PHP files ending with Test.php in the test directory.
 */
$files = glob($testDir . '/*Test.php');

/**
 * Store the execution results of each test suite.
 */
$results = [];

/**
 * Keep track of whether all tests passed.
 */
$allPassed = true;

echo "================================================\n";
echo " GLPI SAMLSSO Plugin - Automated Test Runner\n";
echo "================================================\n\n";

/**
 * Execute each test file in a separate PHP CLI process.
 */
foreach ($files as $file) {
    $filename = basename($file);

    $output = [];
    $returnCode = 0;

    /**
     * Require the suite through a wrapper that confirms control returns normally.
     * A production exit(0) must not silently mark a partially executed suite as passing.
     */
    $completionMarker = 'SAMLSSO_SUITE_COMPLETED_' . bin2hex(random_bytes(16));
    $wrapper = 'require $argv[1]; echo "\n", $argv[2], "\n";';
    /** Pass arguments directly so Windows shell quoting cannot alter the PHP wrapper. */
    $process = proc_open(
        [PHP_BINARY, '-d', 'error_reporting=-1', '-d', 'display_errors=stderr',
            '-d', 'log_errors=0', '-d', 'html_errors=0', '-r', $wrapper, '--', $file, $completionMarker],
        [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['redirect', 1]],
        $pipes
    );
    if (is_resource($process)) {
        fclose($pipes[0]);
        $output = preg_split('/\r?\n/', (string) stream_get_contents($pipes[1]));
        fclose($pipes[1]);
        $returnCode = proc_close($process);
    } else {
        $output = ['Unable to start the isolated test process.'];
        $returnCode = 1;
    }

    if ($returnCode === 0 && !in_array($completionMarker, $output, true)) {
        $output[] = 'Suite exited before its completion marker; remaining assertions may not have run.';
        $returnCode = 1;
    }

    /** A zero exit status must not hide diagnostics emitted under the pinned CLI error settings. */
    $diagnosticPattern = '/^(?:PHP )?(?:Warning|Notice|Deprecated|Fatal error|Parse error):/m';
    if ($returnCode === 0 && preg_match($diagnosticPattern, implode("\n", $output))) {
        $returnCode = 1;
    }

    if ($returnCode === 0) {
        $results[$filename] = '✅ PASSED';

        /**
         * Print individual success symbols/lines from the test output to show granular progress.
         */
        foreach ($output as $line) {
            $trimmedLine = trim($line);
            if (str_starts_with($trimmedLine, '✅')) {
                echo $trimmedLine . "\n";
            }
        }
    } else {
        $results[$filename] = '❌ FAILED';
        $allPassed = false;

        /**
         * Output full details of the failure for debugging purposes.
         */
        echo "--- FAIL: $filename ---\n";
        echo implode("\n", $output) . "\n\n";
    }
}

echo "\n================================================\n";
echo " FINAL SUMMARY\n";
echo "================================================\n";

/**
 * Print the summary table containing the status of each test suite.
 */
foreach ($results as $test => $status) {
    echo str_pad($test, 30) . " $status\n";
}
echo "================================================\n";

/**
 * Exit with an error code if any test suite failed, to support CI/CD integration.
 */
if ($allPassed) {
    echo "Overall Status: ALL TESTS PASSED! 🚀\n";
} else {
    echo "Overall Status: SOME TESTS FAILED! 🛑\n";
    exit(1);
}
