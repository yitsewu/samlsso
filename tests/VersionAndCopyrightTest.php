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

namespace GlpiPlugin\Samlsso\Tests {

    require_once __DIR__ . '/Shims.php';
    require_once __DIR__ . '/TestHarness.php';

    /**
     * Class VersionAndCopyrightTest
     *
     * Validates that all codebase PHP files contain the standard copyright header,
     * that their @version tags align with the version declared in setup.php, and
     * that samlsso.xml is syntactically valid and has the correct version download listed.
     */
    class VersionAndCopyrightTest {

        /**
         * Test that all PHP files contain the correct copyright header and matching version.
         *
         * @throws \Exception if any file is missing the copyright header or has an outdated version.
         */
        public function testPhpFilesCopyrightAndVersion(): void {
            $basePath = realpath(__DIR__ . '/..');
            if ($basePath === false) {
                throw new \UnexpectedValueException("Could not resolve base path.");
            }

            $setupPath = $basePath . '/setup.php';
            if (!file_exists($setupPath)) {
                throw new \UnexpectedValueException("setup.php not found at $setupPath");
            }

            $setupContent = file_get_contents($setupPath);
            if ($setupContent === false) {
                throw new \UnexpectedValueException("Failed to read setup.php");
            }

            if (!preg_match("/define\('PLUGIN_SAMLSSO_VERSION',\s*'([^']+)'\)/", $setupContent, $matches)) {
                throw new \UnexpectedValueException("PLUGIN_SAMLSSO_VERSION definition not found in setup.php");
            }

            $targetVersion = $matches[1];
            $errors = [];

            $directoryIterator = new \RecursiveDirectoryIterator($basePath);
            $iterator = new \RecursiveIteratorIterator($directoryIterator);

            foreach ($iterator as $file) {
                if ($file->isFile() && $file->getExtension() === 'php') {
                    $filePath = $file->getRealPath();
                    if ($filePath === false) {
                        continue;
                    }

                    if (str_contains($filePath, '/vendor/')) {
                        continue;
                    }

                    $content = file_get_contents($filePath);
                    if ($content === false) {
                        $errors[] = "$filePath: Failed to read file.";
                        continue;
                    }

                    if (!preg_match('/Copyright\s*\(C\)\s*2024\s*(by)?\s*Chris Gralike/i', $content)) {
                        $errors[] = "$filePath: Missing copyright header.";
                        continue;
                    }

                    if (!preg_match('/@version\s+([0-9\.]+)/', $content, $vMatches)) {
                        $errors[] = "$filePath: Missing @version tag in header.";
                        continue;
                    }

                    $fileVersion = $vMatches[1];
                    if ($fileVersion !== $targetVersion) {
                        $errors[] = "$filePath: Version mismatch. Expected '$targetVersion', found '$fileVersion'.";
                    }
                }
            }

            if (!empty($errors)) {
                throw new \UnexpectedValueException("Version/Copyright validation failed:\n" . implode("\n", $errors));
            }

            echo "✅ Validated all PHP files: Copyright headers present and versions aligned.\n";
        }

        /**
         * Validate every published entry without inventing an unreleased download.
         * Release builds additionally require the exact packaged version in the catalog.
         *
         * @throws \UnexpectedValueException for malformed, duplicate, missing or inconsistent entries.
         */
        public static function validateReleaseCatalog(
            \SimpleXMLElement $xml,
            string $targetVersion,
            string $changelog,
            bool $release
        ): void {
            $versions = [];
            foreach ($xml->versions->version as $entry) {
                $version = (string) $entry->num;
                $url = (string) $entry->download_url;
                $expected = 'https://github.com/DonutsNL/samlsso/releases/download/v' . $version . '/samlsso.zip';
                $legacy = 'https://github.com/DonutsNL/glpisaml/releases/download/v' . $version . '/glpisaml.zip';
                $validUrl = $url === $expected || (version_compare($version, '1.2.0', '<') && $url === $legacy);
                if (!preg_match('/^\d+\.\d+\.\d+$/D', $version) || isset($versions[$version]) || !$validUrl) {
                    throw new \UnexpectedValueException('Invalid or duplicate release catalog entry.');
                }
                $versions[$version] = true;
            }
            if ($versions === []) {
                throw new \UnexpectedValueException('Release catalog is empty.');
            }
            if (isset($versions[$targetVersion])) {
                return;
            }
            $declared = preg_match('/^\*\*V' . preg_quote($targetVersion, '/') . '\*\*$/m', $changelog) === 1;
            foreach (array_keys($versions) as $version) {
                if (version_compare($targetVersion, $version, '<=')) {
                    throw new \UnexpectedValueException('Missing version is not newer than published releases.');
                }
            }
            if ($release || !$declared) {
                throw new \UnexpectedValueException('Packaged version must be listed, or explicitly declared as development.');
            }
        }

        /** Exercise development acceptance and strict release rejection using local fixtures. */
        public function testReleaseCatalogPolicy(): void
        {
            $publishedVersion = '1.0.0';
            $developmentVersion = '1.1.0';
            $developmentEntry = '**V1.1.0**';
            $xml = simplexml_load_string('<root><versions><version><num>1.0.0</num>'
                . '<download_url>https://github.com/DonutsNL/samlsso/releases/download/v1.0.0/samlsso.zip</download_url>'
                . '</version></versions></root>');
            self::validateReleaseCatalog($xml, $publishedVersion, '', true);
            self::validateReleaseCatalog($xml, $developmentVersion, $developmentEntry, false);
            $cases = [
                [$xml, $developmentVersion, $developmentEntry, true],
                [$xml, $developmentVersion, '', false],
                [$xml, '0.9.0', '**V0.9.0**', false],
                [simplexml_load_string('<root><versions/></root>'), $developmentVersion, $developmentEntry, false],
            ];
            $badUrl = simplexml_load_string($xml->asXML());
            $badUrl->versions->version->download_url = 'https://untrusted.example/download.zip';
            $cases[] = [$badUrl, $publishedVersion, '', true];
            $duplicate = simplexml_load_string(str_replace('</versions>',
                $xml->versions->version->asXML() . '</versions>', $xml->asXML()));
            $cases[] = [$duplicate, $publishedVersion, '', true];
            foreach ($cases as $case) {
                try {
                    self::validateReleaseCatalog(...$case);
                } catch (\UnexpectedValueException $expected) {
                    continue;
                }
                throw new \UnexpectedValueException('Invalid release policy fixture was accepted.');
            }
            echo "✅ Development builds remain distinct from strict release validation.\n";
        }

        /**
         * Test that samlsso.xml is valid XML and has the required version download listed.
         *
         * @throws \Exception if samlsso.xml is invalid or missing the required version block.
         */
        public function testSamlSsoXmlValidityAndDownload(): void {
            $basePath = realpath(__DIR__ . '/..');
            if ($basePath === false) {
                throw new \UnexpectedValueException("Could not resolve base path.");
            }

            $setupPath = $basePath . '/setup.php';
            if (!file_exists($setupPath)) {
                throw new \UnexpectedValueException("setup.php not found at $setupPath");
            }

            $setupContent = file_get_contents($setupPath);
            if ($setupContent === false) {
                throw new \UnexpectedValueException("Failed to read setup.php");
            }

            if (!preg_match("/define\('PLUGIN_SAMLSSO_VERSION',\s*'([^']+)'\)/", $setupContent, $matches)) {
                throw new \UnexpectedValueException("PLUGIN_SAMLSSO_VERSION definition not found in setup.php");
            }

            $targetVersion = $matches[1];

            $xmlPath = $basePath . '/samlsso.xml';
            if (!file_exists($xmlPath)) {
                throw new \UnexpectedValueException("samlsso.xml not found at $xmlPath");
            }

            libxml_use_internal_errors(true);
            $xml = simplexml_load_file($xmlPath);
            if ($xml === false) {
                $xmlErrors = libxml_get_errors();
                $errMsgs = [];
                foreach ($xmlErrors as $err) {
                    $errMsgs[] = trim($err->message) . " on line " . $err->line;
                }
                libxml_clear_errors();
                throw new \UnexpectedValueException("samlsso.xml is not valid XML:\n" . implode("\n", $errMsgs));
            }

            $changelog = file_get_contents($basePath . '/changelog.md');
            self::validateReleaseCatalog($xml, $targetVersion, $changelog, getenv('SAMLSSO_RELEASE_VALIDATION') === '1');
            echo "✅ Validated release catalog and explicit development/release policy.\n";
        }
    }
}

namespace {
    /**
     * Executes the VersionAndCopyrightTest test suite.
     */
    $test = new GlpiPlugin\Samlsso\Tests\VersionAndCopyrightTest();
    try {
        $test->testPhpFilesCopyrightAndVersion();
        $test->testSamlSsoXmlValidityAndDownload();
        $test->testReleaseCatalogPolicy();
        $test = null;
    } catch (\Exception $e) {
        echo "\n❌ Test Failed: " . $e->getMessage() . "\n";
        exit(1);
    }
}
