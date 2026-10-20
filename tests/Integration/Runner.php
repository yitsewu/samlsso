<?php

/**
 * Execute native framework cases and record measured method coverage.
 *
 * @package samlSSO
 * @version 1.3.2
 * @copyright Copyright (c) 2024 by Chris Gralike
 * @license GPLv3+
 */

declare(strict_types=1);

use GlpiPlugin\Samlsso\LoginFlow;
use GlpiPlugin\Samlsso\LoginFlow\Acs;

if (!function_exists('xdebug_start_code_coverage')) {
    throw new RuntimeException(
        'The native gate requires Xdebug with coverage enabled; unavailable coverage is a failure.'
    );
}
/** Keep native session/header operations possible until every case has completed. */
ob_start();
$context = require __DIR__ . '/Bootstrap.php';
foreach ([GlpiPlugin\Samlsso\Config::class, GlpiPlugin\Samlsso\LoginState::class] as $class) {
    if (!$context->db()->tableExists($class::getTable())) {
        throw new RuntimeException('Plugin schema is missing; explicitly run Integration/Provision.php first.');
    }
}

$cases = [];
foreach (glob(__DIR__ . '/*Cases.php') as $path) {
    $declared = (static fn(string $suite): mixed => require $suite)($path);
    if (!is_array($declared) || $declared === [] || array_intersect_key($cases, $declared) !== []) {
        throw new RuntimeException('A native suite returned no cases or duplicate case identifiers: '
            . basename($path));
    }
    $cases += $declared;
}
if ($cases === []) {
    throw new RuntimeException('No native integration cases were discovered.');
}

$results = [];
$measured = [];
$lineCoverage = [];
$filter = (string) getenv('SAMLSSO_INTEGRATION_CASE_FILTER');
$selectedCase = (string) getenv('SAMLSSO_NATIVE_CASE');
foreach ($cases as $name => $case) {
    if ($selectedCase !== '' && $name !== $selectedCase) {
        continue;
    }
    if ($filter !== '' && !str_contains($name, $filter)) {
        continue;
    }
    if (!is_callable($case['run'] ?? null) || !is_array($case['covers'] ?? null)) {
        throw new RuntimeException('Invalid native case declaration: ' . $name);
    }
    if ($selectedCase === '') {
        /** Each case gets a new framework process so native static caches cannot leak between transactions. */
        $reportFile = tempnam(sys_get_temp_dir(), 'samlsso-native-case-');
        if ($reportFile === false) {
            throw new RuntimeException('Cannot create the isolated case report.');
        }
        $marker = 'SAMLSSO_NATIVE_CASE_COMPLETED_' . bin2hex(random_bytes(16));
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
            '-d',
            'log_errors=0',
            '-d',
            'html_errors=0',
            '-r',
            'require $argv[1]; echo "\n", $argv[2], "\n";',
            '--',
            __FILE__,
            $marker
        );
        $environment = getenv();
        $environment['SAMLSSO_NATIVE_CASE'] = $name;
        $environment['SAMLSSO_COVERAGE_FILE'] = $reportFile;
        try {
            $process = proc_open($command, [0 => ['pipe', 'r'], 1 => ['pipe', 'w'],
                 2 => ['redirect', 1]], $pipes, null, $environment);
            if (!is_resource($process)) {
                throw new RuntimeException('Cannot start native case process: ' . $name);
            }
            fclose($pipes[0]);
            $output = (string) stream_get_contents($pipes[1]);
            fclose($pipes[1]);
            $status = proc_close($process);
            $reportData = file_get_contents($reportFile);
            $child = $reportData !== '' ? json_decode($reportData, true, 512, JSON_THROW_ON_ERROR) : null;
            $passed = $status === 0 && in_array($marker, preg_split('/\r?\n/', $output), true)
                && !preg_match('/^(?:PHP )?(?:Warning|Notice|Deprecated|Fatal error|Parse error):/m', $output)
                && isset($child['cases'][$name]) && $child['cases'][$name]['passed'] === true;
            $results[$name] = $child['cases'][$name] ?? ['passed' => false, 'covers' => $case['covers']];
            $results[$name]['passed'] = $passed;
            foreach ($child['methods'] ?? [] as $method => $methodCases) {
                $measured[$method] = array_merge($measured[$method] ?? [], $methodCases);
            }
            foreach ($child['line_coverage'] ?? [] as $source => $coverage) {
                foreach ($coverage['executable_lines'] as $line) {
                    $lineCoverage[$source]['executable'][(int) $line] = true;
                }
                foreach ($coverage['covered_lines'] as $line) {
                    $lineCoverage[$source]['covered'][(int) $line] = true;
                }
            }
            echo ($passed ? 'PASS ' : 'FAIL ') . $name . "\n";
            if (!$passed) {
                echo $output;
            }
        } finally {
            unlink($reportFile);
        }
        continue;
    }
    $failure = null;
    $returned = null;
    $diagnostics = [];
    set_error_handler(static function (
        int $severity,
        string $message,
        string $file,
        int $line
    ) use (&$diagnostics): bool {
        if ((error_reporting() & $severity) === 0) {
            return false;
        }
        $diagnostics[] = $message . ' at ' . $file . ':' . $line;
        throw new ErrorException($message, 0, $severity, $file, $line);
    });
    $context->begin();
    xdebug_start_code_coverage(XDEBUG_CC_UNUSED | XDEBUG_CC_DEAD_CODE);
    try {
        $returned = $case['run']($context);
    } catch (Throwable $error) {
        $failure = $error;
    } finally {
        $lines = xdebug_get_code_coverage();
        xdebug_stop_code_coverage();
        $context->rollback();
        restore_error_handler();
    }
    if ($diagnostics !== [] && $failure === null) {
        $failure = new RuntimeException('A diagnostic was caught inside production code: '
            . implode('; ', $diagnostics));
    }
    $executed = [];
    if (isset($returned['native_child_coverage']) && is_array($returned['native_child_coverage'])) {
        foreach ($returned['native_child_coverage'] as $file => $childHits) {
            foreach ($childHits as $line => $count) {
                /** Retain executable-but-uncovered lines; a positive hit takes precedence over either status. */
                if (!isset($lines[$file][$line]) || $count > $lines[$file][$line]) {
                    $lines[$file][$line] = $count;
                }
            }
        }
    }
    foreach ($lines as $file => $hits) {
        $canonical = str_replace('\\', '/', (string) realpath($file));
        foreach ($hits as $line => $count) {
            /** Xdebug -2 marks dead code; -1 is executable and must remain in the denominator. */
            if ($count >= -1) {
                $lineCoverage[$canonical]['executable'][(int) $line] = true;
            }
            if ($count > 0) {
                $executed[$canonical][(int) $line] = true;
                $lineCoverage[$canonical]['covered'][(int) $line] = true;
            }
        }
    }
    foreach ($case['covers'] as $methodName) {
        [$className, $memberName] = explode('::', $methodName, 2);
        $method = new ReflectionMethod($className, $memberName);
        $file = str_replace('\\', '/', (string) realpath($method->getFileName()));
        $hit = false;
        foreach ($executed[$file] ?? [] as $line => $unused) {
            if ($line >= $method->getStartLine() && $line <= $method->getEndLine()) {
                $hit = true;
                break;
            }
        }
        if (!$hit && $failure === null) {
            $failure = new RuntimeException('Declared method was not executed: ' . $methodName);
        }
        if ($hit) {
            $measured[$methodName][] = $name;
        }
    }
    $results[$name] = ['passed' => $failure === null, 'covers' => $case['covers']];
    if ($failure !== null) {
        $results[$name]['error_type'] = $failure::class;
        $results[$name]['error'] = $failure->getMessage();
        echo 'FAIL ' . $name . ': ' . $failure::class . ': ' . $failure->getMessage() . "\n";
    } else {
        echo 'PASS ' . $name . "\n";
    }
}
if ($results === []) {
    throw new RuntimeException('The case filter selected no native tests.');
}

$missing = [];
if ($filter === '' && $selectedCase === '') {
    foreach ([LoginFlow::class, Acs::class] as $class) {
        foreach ((new ReflectionClass($class))->getMethods() as $method) {
            if ($method->getDeclaringClass()->getName() !== $class) {
                continue;
            }
            $identifier = $class . '::' . $method->getName();
            if (!isset($measured[$identifier])) {
                $missing[] = $identifier;
            }
        }
    }
}

/** Report measured line coverage separately from method execution; neither claims branch coverage. */
$lineReport = [];
foreach ($lineCoverage as $file => $coverage) {
    $executable = array_keys($coverage['executable'] ?? []);
    $covered = array_keys($coverage['covered'] ?? []);
    sort($executable);
    sort($covered);
    $lineReport[$file] = [
        'executable_count' => count($executable),
        'covered_count' => count($covered),
        'line_percent' => $executable === [] ? null : round(count($covered) / count($executable) * 100, 2),
        'executable_lines' => $executable,
        'covered_lines' => $covered,
        'uncovered_lines' => array_values(array_diff($executable, $covered)),
    ];
}
ksort($lineReport);
$requiredLineReport = [];
foreach ([LoginFlow::class, Acs::class] as $class) {
    $file = str_replace('\\', '/', (string) realpath((new ReflectionClass($class))->getFileName()));
    $requiredLineReport[$class] = $lineReport[$file] ?? null;
}
$report = [
    'glpi_version' => GLPI_VERSION,
    'php_version' => PHP_VERSION,
    'scope' => $selectedCase !== '' ? 'isolated case: ' . $selectedCase : ($filter === '' ? 'complete' : 'filtered: '
        . $filter),
    'cases' => $results,
    'methods' => $measured,
    'uncovered_required_methods' => $missing,
    'line_coverage_kind' => 'Xdebug executable line coverage; excludes dead lines and is not branch coverage',
    'line_coverage' => $lineReport,
    'required_flow_line_coverage' => $requiredLineReport,
];
$reportPath = getenv('SAMLSSO_COVERAGE_FILE');
if (is_string($reportPath) && $reportPath !== '') {
    if (file_put_contents($reportPath, json_encode($report, JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR)) === false) {
        throw new RuntimeException('Cannot write the requested coverage report.');
    }
}
if ($missing !== []) {
    throw new RuntimeException('Uncovered LoginFlow methods: ' . implode(', ', $missing));
}
if (in_array(false, array_column($results, 'passed'), true)) {
    throw new RuntimeException('At least one native integration case failed.');
}
echo 'Native integration cases completed: ' . count($results) . "\n";
ob_end_flush();
