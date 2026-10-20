<?php

/**
 * Native CGI request entry point with verification after production exit calls.
 *
 * @package samlSSO
 * @version 1.3.2
 * @copyright Copyright (c) 2024 by Chris Gralike
 * @license GPLv3+
 */

declare(strict_types=1);

use GlpiPlugin\Samlsso\Tests\Integration\ProtocolFlowActions;

if (PHP_SAPI !== 'cgi-fcgi' || getenv('SAMLSSO_INTEGRATION_ALLOW_DB') !== '1') {
    throw new RuntimeException('This entry point is restricted to the explicitly enabled native CGI test harness.');
}
$context = require __DIR__ . '/Bootstrap.php';
require_once __DIR__ . '/ProtocolFixtures.php';
require_once __DIR__ . '/ProtocolFlowActions.php';
/** Native post_init can create state during kernel boot; the scenario is a separate browser session. */
if (session_status() === PHP_SESSION_ACTIVE) {
    session_regenerate_id(true);
}
$context->begin();
xdebug_start_code_coverage(XDEBUG_CC_UNUSED | XDEBUG_CC_DEAD_CODE);
$invoked = $returned = false;
$scenario = null;
$failure = null;
$diagnostics = [];
set_error_handler(static function (int $severity, string $message, string $file, int $line) use (&$diagnostics): bool {
    if ((error_reporting() & $severity) === 0) {
        return false;
    }
    $diagnostics[] = $message . ' at ' . $file . ':' . $line;
    throw new ErrorException($message, 0, $severity, $file, $line);
});
register_shutdown_function(static function () use (
    $context,
    &$invoked,
    &$returned,
    &$scenario,
    &$failure,
    &$diagnostics
): void {
    $report = ['completed' => false];
    try {
        $error = error_get_last();
        if ($error !== null && in_array($error['type'], [E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR], true)) {
            throw new RuntimeException('Native CGI fatal error: ' . $error['message']);
        }
        if ($failure !== null) {
            throw $failure;
        }
        $context->assert($diagnostics === [], 'Native CGI emitted a diagnostic: ' . implode('; ', $diagnostics));
        if (!$invoked || !is_array($scenario) || !is_callable($scenario['verify'] ?? null)) {
            throw new RuntimeException('CGI exited before a verifiable scenario invocation.');
        }
        $context->same(
            !($scenario['exits'] ?? false),
            $returned,
            'Production execution ended at an unexpected boundary.'
        );
        ($scenario['verify'])();
        $report['completed'] = true;
    } catch (Throwable $error) {
        $report['error'] = $error->getMessage();
    } finally {
        $report['coverage'] = xdebug_get_code_coverage();
        xdebug_stop_code_coverage();
        restore_error_handler();
        $context->rollback();
        file_put_contents(getenv('SAMLSSO_NATIVE_RESULT'), json_encode($report, JSON_THROW_ON_ERROR));
    }
});
try {
    $scenario = ProtocolFlowActions::create($context, (string) getenv('SAMLSSO_NATIVE_ACTION'));
    $invoked = true;
    ($scenario['invoke'])();
    $returned = true;
} catch (Throwable $error) {
    $failure = $error;
}
