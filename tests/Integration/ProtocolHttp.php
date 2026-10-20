<?php

/**
 * Execute terminal HTTP behavior in a real CGI process, retaining measured coverage.
 *
 * @package samlSSO
 * @version 1.3.2
 * @copyright Copyright (c) 2024 by Chris Gralike
 * @license GPLv3+
 */

declare(strict_types=1);

namespace GlpiPlugin\Samlsso\Tests\Integration;

/** No overridden exit, header, Session, database, or renderer implementation is used. */
final class ProtocolHttp
{
    /**
     * Run one isolated CGI request and require post-exit assertions plus coverage.
     *
     * @param Context $context Native parent context.
     * @param string $action Exact synthetic request scenario.
     * @param array $expectations HTTP response assertions.
     * @return array Child's measured line coverage, for the native runner to merge.
     */
    public static function run(Context $context, string $action, array $expectations): array
    {
        $binary = getenv('SAMLSSO_PHP_CGI');
        $context->assert(
            is_string($binary) && is_file($binary),
            'SAMLSSO_PHP_CGI must point to the real PHP-CGI binary.'
        );
        $ini = getenv('SAMLSSO_PHP_INI') ?: php_ini_loaded_file();
        $command = [$binary];
        if ($ini) {
            $command = [...$command, '-c', $ini];
        }
        $command = [...$command, '-d', 'error_reporting=-1', '-d', 'display_errors=stderr',
            '-d', 'log_errors=0', '-d', 'html_errors=0'];
        $resultPath = tempnam(sys_get_temp_dir(), 'samlsso-native-');
        $context->assert($resultPath !== false, 'Cannot allocate child verification output.');
        $environment = getenv();
        $environment = array_replace($environment, [
            'REDIRECT_STATUS' => '1',
            'GATEWAY_INTERFACE' => 'CGI/1.1',
            'SERVER_PROTOCOL' => 'HTTP/1.1',
            'SERVER_NAME' => 'localhost',
            'SERVER_PORT' => '80',
            'HTTP_HOST' => 'localhost',
            'REMOTE_ADDR' => '127.0.0.1',
            'REQUEST_METHOD' => 'GET',
            'REQUEST_URI' => '/index.php',
            'SCRIPT_NAME' => '/index.php',
            'SCRIPT_FILENAME' => __DIR__ . '/ProtocolChild.php',
            'DOCUMENT_ROOT' => $context->runtime . '/public',
            'QUERY_STRING' => '',
            'SAMLSSO_NATIVE_ACTION' => $action,
            'SAMLSSO_NATIVE_RESULT' => $resultPath,
            'XDEBUG_MODE' => 'coverage',
        ]);
        try {
            $descriptors = [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']];
            $process = proc_open($command, $descriptors, $pipes, null, $environment);
            $context->assert(is_resource($process), 'Could not start the actual CGI request.');
            fclose($pipes[0]);
            $output = stream_get_contents($pipes[1]);
            $diagnostics = stream_get_contents($pipes[2]);
            fclose($pipes[1]);
            fclose($pipes[2]);
            $exit = proc_close($process);
            $report = json_decode((string) file_get_contents($resultPath), true);
            $context->assert(is_array($report), 'CGI ended before native verification was installed: ' . $diagnostics);
            $context->assert(
                ($report['completed'] ?? false) === true,
                'CGI verification failed: ' . ($report['error'] ?? 'early exit')
            );
            $context->same(0, $exit, 'CGI exited unsuccessfully.');
            $context->same('', trim($diagnostics), 'CGI emitted diagnostics.');
            $parts = preg_split('/\r?\n\r?\n/', $output, 2);
            $context->same(2, count($parts), 'CGI did not emit an HTTP header/body boundary.');
            [$headers, $body] = $parts;
            $status = preg_match('/^Status:\s*(\d+)/mi', $headers, $matches) ? (int) $matches[1] : 200;
            $context->same($expectations['status'] ?? 200, $status, 'Unexpected CGI HTTP status.');
            foreach ($expectations['body'] ?? [] as $needle) {
                $context->assert(str_contains($body, $needle), 'CGI body omitted expected content: ' . $needle);
            }
            if (isset($expectations['location'])) {
                $context->assert(
                    preg_match('/^Location:\s*(.+)$/mi', $headers, $matches) === 1,
                    'CGI redirect omitted Location.'
                );
                $context->assert(
                    str_starts_with(trim($matches[1]), $expectations['location']),
                    'CGI redirected to an unexpected target.'
                );
            }
            $context->assert(!empty($report['coverage']), 'CGI returned no measured coverage.');
            return ['native_child_coverage' => $report['coverage']];
        } finally {
            unlink($resultPath);
        }
    }
}
