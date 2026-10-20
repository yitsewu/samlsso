<?php

/**
 * Report failures of the standalone samlSSO maintenance command.
 *
 * @package samlSSO
 * @version 1.3.2
 * @copyright Copyright (c) 2024 by Chris Gralike
 * @license GPLv3+
 */

declare(strict_types=1);

namespace GlpiPlugin\Samlsso\Exception;

use RuntimeException;

/** Maintenance could not start or its database validation did not succeed. */
final class PluginMaintenanceException extends RuntimeException
{
}
