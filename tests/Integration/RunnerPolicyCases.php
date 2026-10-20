<?php

/**
 * Exercise the public runner as a real process so focused runs cannot pass a release gate.
 *
 * @package samlSSO
 * @version 1.3.2
 * @copyright Copyright (c) 2024 by Chris Gralike
 * @license GPLv3+
 */

declare(strict_types=1);

use GlpiPlugin\Samlsso\Tests\Integration\Context;

/**
 * Invoke the actual runner with an explicit environment, without replacing its bootstrap or framework.
 *
 * @param Context $context Current native fixture context.
 * @param array $overrides Environment variables for this process boundary.
 * @return array{status: int, output: string} Actual subprocess exit status and merged output.
 */
$invokeRunner = static function (Context $context, array $overrides): array {
    $environment = getenv();
    foreach (
        [
        'SAMLSSO_NATIVE_CASE',
        'SAMLSSO_INTEGRATION_CASE_FILTER',
        'SAMLSSO_RELEASE_VALIDATION',
        'SAMLSSO_COVERAGE_FILE',
        ] as $variable
    ) {
        unset($environment[$variable]);
    }
    $environment = array_replace($environment, $overrides);
    $command = [PHP_BINARY];
    if (($ini = php_ini_loaded_file()) !== false) {
        array_push($command, '-c', $ini);
    }
    array_push(
        $command,
        '-d',
        'error_reporting=-1',
        '-d',
        'display_errors=stderr',
        $context->pluginRoot . '/tests/RunAllTests.php'
    );
    $process = proc_open(
        $command,
        [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['redirect', 1]],
        $pipes,
        null,
        $environment
    );
    $context->assert(is_resource($process), 'Could not execute the public runner policy fixture.');
    fclose($pipes[0]);
    $output = (string) stream_get_contents($pipes[1]);
    fclose($pipes[1]);
    return ['status' => proc_close($process), 'output' => $output];
};

return [
    'runner_policy.reject_external_case_selector' => [
        'covers' => [],
        'run' => static function (Context $context) use ($invokeRunner): void {
            foreach (['0', '1'] as $release) {
                $result = $invokeRunner($context, [
                    'SAMLSSO_NATIVE_CASE' => 'repository.release_catalog',
                    'SAMLSSO_RELEASE_VALIDATION' => $release,
                    'SAMLSSO_GLPI_ROOT' => '',
                    'SAMLSSO_INTEGRATION_ALLOW_DB' => '0',
                ]);
                $context->same(1, $result['status'], 'External case selection did not fail before bootstrap.');
                $context->assert(
                    str_contains($result['output'], 'SAMLSSO_NATIVE_CASE is reserved'),
                    'External case selection reached framework bootstrap instead of the preflight rejection.'
                );
                $context->assert(
                    !str_contains($result['output'], 'ALL TESTS PASSED'),
                    'External case selection was reported as a complete suite.'
                );
            }
        },
    ],
    'runner_policy.reject_release_filter' => [
        'covers' => [],
        'run' => static function (Context $context) use ($invokeRunner): void {
            $result = $invokeRunner($context, [
                'SAMLSSO_RELEASE_VALIDATION' => '1',
                'SAMLSSO_INTEGRATION_CASE_FILTER' => 'maintenance.',
                'SAMLSSO_GLPI_ROOT' => '',
                'SAMLSSO_INTEGRATION_ALLOW_DB' => '0',
            ]);
            $context->same(1, $result['status'], 'Filtered release validation did not fail before bootstrap.');
            $context->assert(
                str_contains($result['output'], 'Release validation requires the complete suite'),
                'Filtered release validation reached bootstrap instead of the preflight rejection.'
            );
            $context->assert(
                !str_contains($result['output'], 'ALL TESTS PASSED'),
                'Filtered release validation was reported as a complete suite.'
            );
        },
    ],
    'runner_policy.focused_run_is_explicit' => [
        'covers' => [],
        'run' => static function (Context $context) use ($invokeRunner): void {
            $result = $invokeRunner($context, [
                'SAMLSSO_INTEGRATION_CASE_FILTER' => 'repository.release_policy_rejects_invalid_candidates',
            ]);
            $context->same(0, $result['status'], 'The permitted native focused run failed.');
            $context->assert(
                str_contains($result['output'], 'PASS repository.release_policy_rejects_invalid_candidates'),
                'The focused subprocess did not execute its actual native case.'
            );
            $context->assert(
                str_contains($result['output'], 'the complete integration and coverage gate was NOT run'),
                'Focused success omitted the incomplete-gate notice.'
            );
            $context->assert(
                !str_contains($result['output'], 'ALL TESTS PASSED'),
                'Focused success was reported as a complete suite.'
            );
        },
    ],
];
