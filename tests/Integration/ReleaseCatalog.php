<?php

/**
 * Validate development and release catalog policy without publishing a release.
 *
 * @package samlSSO
 * @version 1.3.2
 * @copyright Copyright (c) 2024 by Chris Gralike
 * @license GPLv3+
 */

declare(strict_types=1);

namespace GlpiPlugin\Samlsso\Tests\Integration;

use SimpleXMLElement;
use UnexpectedValueException;

/** Release metadata validation is independent of the framework behavior coverage map. */
final class ReleaseCatalog
{
    /**
     * Require consistent published entries and an explicit development or release version.
     *
     * @param SimpleXMLElement $catalog Parsed release catalog.
     * @param string $targetVersion Candidate version from the actual plugin metadata or a policy fixture.
     * @param string $changelog Changelog content used to identify an unpublished development version.
     * @param bool $release Whether this invocation prepares a release archive.
     * @return void
     * @throws UnexpectedValueException When an entry or the requested version violates release policy.
     */
    public static function validate(
        SimpleXMLElement $catalog,
        string $targetVersion,
        string $changelog,
        bool $release
    ): void {
        $versions = [];
        foreach ($catalog->versions->version as $entry) {
            $version = (string) $entry->num;
            $url = (string) $entry->download_url;
            $expected = 'https://github.com/DonutsNL/samlsso/releases/download/v' . $version . '/samlsso.zip';
            $legacy = 'https://github.com/DonutsNL/glpisaml/releases/download/v' . $version . '/glpisaml.zip';
            $validUrl = $url === $expected || (version_compare($version, '1.2.0', '<') && $url === $legacy);
            if (!preg_match('/^\d+\.\d+\.\d+$/D', $version) || isset($versions[$version]) || !$validUrl) {
                throw new UnexpectedValueException('Invalid or duplicate release catalog entry.');
            }
            $versions[$version] = true;
        }
        if ($versions === []) {
            throw new UnexpectedValueException('Release catalog is empty.');
        }
        if (isset($versions[$targetVersion])) {
            return;
        }
        $declared = preg_match('/^\*\*V' . preg_quote($targetVersion, '/') . '\*\*\r?$/m', $changelog) === 1;
        foreach (array_keys($versions) as $version) {
            if (version_compare($targetVersion, $version, '<=')) {
                throw new UnexpectedValueException('Missing version is not newer than published releases.');
            }
        }
        if ($release || !$declared) {
            throw new UnexpectedValueException(
                'Packaged version must be listed, or explicitly declared as development.'
            );
        }
    }
}
