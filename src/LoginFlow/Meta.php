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

namespace GlpiPlugin\Samlsso\LoginFlow;

use Exception;
use OneLogin\Saml2\Settings;

/** Required to generate XML metadata */
/** Required to fetch requested SAML configuration */
use GlpiPlugin\Samlsso\Config\ConfigEntity;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 *  Responsible to handle any requests for Metadata.
 *  invoked by the MetaController.
 */
class Meta
{
    /** Prevent repetition */
    public const STAG  = '<xml><error>';
    /** Prevent repetition */
    public const ETAG  = '</error></xml>';

    /**
     * Evaluate the getSPMeta configuration value.
     *
     * @param Request $request Incoming metadata request containing the provider identifier.
     * @return Response XML service provider metadata.
     */
    final public function getSPMeta(Request $request): Response
    {

        /** Did we get a valid ID? */
        $id = (filter_var($request->get('idpId'), FILTER_VALIDATE_INT)) ?
            /** Then assign it */
            (int) $request->get('idpId') :
            /** Else fall back to -1 */
            -1;

        /** If we have an ID then try to build the metadata. */
        try {
            /** ConfigEntity expects/validates datatype INT. */
            $configEntity = new ConfigEntity($id);
            /** Are we allowed to expose metadata. */
            if ($configEntity->getField(ConfigEntity::DEBUG)) {
                /** Get the samlConfig using the provided ID. */
                $samlSettings = new Settings($configEntity->getPhpSamlConfig());
                $metadata = $samlSettings->getSPMetadata();
                /** Get the Serviceprovider metadata. */
                if (!$metadata) {
                    /** Set error if something is wrong */
                    $metadata = self::STAG .
                        __("Error fetching spMetadata.", PLUGIN_NAME) .
                        self::ETAG;
                }
            } else {
                /** Set error if something is wrong */
                $metadata = self::STAG .
                    __("Invalid id or metadata not exposed.", PLUGIN_NAME) .
                    self::ETAG;
            }
        } catch (Exception) {
            /** Set error if something is wrong */
            $metadata = self::STAG .
                __("Error fetching config.", PLUGIN_NAME) .
                self::ETAG;
        }

        /** Return the result to the calling object. */
        return new Response($metadata, 200, ['Content-Type' => 'text/xml']);
    }
}
