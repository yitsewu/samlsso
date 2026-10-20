<?php

/**
 * Synthetic SAML messages and persisted fixtures for the real GLPI framework.
 *
 * @package samlSSO
 * @version 1.3.2
 * @copyright Copyright (c) 2024 by Chris Gralike
 * @license GPLv3+
 */

declare(strict_types=1);

namespace GlpiPlugin\Samlsso\Tests\Integration;

use DOMDocument;
use Glpi\Plugin\Hooks;
use GlpiPlugin\Samlsso\Config\ConfigEntity;
use GlpiPlugin\Samlsso\Controller\SamlSsoController;
use GlpiPlugin\Samlsso\LoginState;
use OneLogin\Saml2\Constants;
use OneLogin\Saml2\Utils;
use OpenSSLAsymmetricKey;
use RuntimeException;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/** Fixture data never substitutes for a GLPI, plugin, or toolkit implementation. */
final class ProtocolFixtures
{
    public const IDP_ENTITY = 'https://idp.example.invalid/metadata';
    public const IDP_LOGOUT = 'https://idp.example.invalid/logout';
    public const REQUEST_ID = '_native_logout_request';
    public const RELAY_STATE = 'native fixture relay';
    public const NAME_ID = 'native-fixture-owner';
    public const SESSION_INDEX = '_native-fixture-session';
    public const RSA_SHA256 = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';
    public const RSA_SHA384 = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha384';
    public const RSA_SHA512 = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512';
    public const RSA_SHA1 = 'http://www.w3.org/2000/09/xmldsig#rsa-sha1';

    public readonly ConfigEntity $provider;
    public readonly int $providerId;
    public readonly array $settings;
    public readonly string $callback;
    public readonly string $idpCertificate;
    public readonly string $idpPrivateKey;
    public readonly string $spCertificate;
    public readonly string $relayState;
    private OpenSSLAsymmetricKey $idpKey;

    /**
     * Create a genuine persisted provider with independent ephemeral signing keys.
     *
     * @param Context $context Native GLPI fixture and assertion helpers.
     * @param array $options Provider flags or explicit configuration overrides.
     * @throws RuntimeException If cryptography or native configuration creation fails.
     */
    public function __construct(private readonly Context $context, array $options = [])
    {
        global $CFG_GLPI;

        $this->relayState = $options['relay'] ?? self::RELAY_STATE;
        [$this->idpKey, $this->idpCertificate, $this->idpPrivateKey] = $this->certificate('idp.example.invalid');
        [, $this->spCertificate, $spPrivateKey] = $this->certificate('sp.example.invalid');
        $origin = ($options['forwarded'] ?? false) ? 'https://sp.example.invalid:8443' : 'https://sp.example.invalid';
        $CFG_GLPI['url_base'] = $origin;
        $CFG_GLPI['root_doc'] = '';
        $this->provider = $context->createProvider(($options['provider'] ?? []) + [
            ConfigEntity::SP_CERTIFICATE => $this->spCertificate,
            ConfigEntity::SP_KEY => $spPrivateKey,
            ConfigEntity::IDP_CERTIFICATE => $this->idpCertificate,
            ConfigEntity::IDP_ENTITY_ID => self::IDP_ENTITY,
            ConfigEntity::IDP_SSO_URL => 'https://idp.example.invalid/sso',
            ConfigEntity::IDP_SLO_URL => self::IDP_LOGOUT,
            ConfigEntity::SP_NAME_FORMAT => Constants::NAMEID_UNSPECIFIED,
            ConfigEntity::STRICT => 1,
            ConfigEntity::DEBUG => 0,
            ConfigEntity::ENFORCE_SSO => 0,
            ConfigEntity::PROXIED => ($options['proxied'] ?? false) ? 1 : 0,
            ConfigEntity::IS_ACTIVE => ($options['active'] ?? true) ? 1 : 0,
            ConfigEntity::SIGN_SLO_RES => ($options['sign_response'] ?? false) ? 1 : 0,
            ConfigEntity::SECURITY_WANTMESSAGESSIGNED => 1,
            ConfigEntity::SECURITY_WANTASSERTIONSSIGNED => 1,
            ConfigEntity::SECURITY_WANTASSERTIONSENCRYPTED => 0,
            ConfigEntity::COMPRESS_RES => 1,
            ConfigEntity::REQUEST_TIMEOUT => 15,
            ConfigEntity::INACTIVITY_TIMEOUT => 0,
        ]);
        $this->settings = $this->provider->getPhpSamlConfig();
        $this->callback = $this->settings['sp']['singleLogoutService']['url'];
        $this->providerId = (int) $this->provider->getDBFields()[ConfigEntity::ID];
        $context->assert($this->providerId > 0, 'Native provider omitted its database ID.');
        $this->requestEnvironment($options);
    }

    /**
     * Authenticate a native user and persist the production state through its real APIs.
     *
     * @param array $options Correlation and authentication variants for a case.
     * @return LoginState Persisted state, whose ID remains available after cleanup.
     * @throws RuntimeException If a native login or database write fails.
     */
    public function loginState(array $options = []): LoginState
    {
        $user = $this->context->createUser();
        $this->context->login($user);
        $state = new LoginState();
        if ($state->getStateId() < 1) {
            $this->context->assert($state->writeState(), 'Could not persist the native login state.');
        }
        $this->context->assert($state->setIdpId($this->providerId), 'Could not associate the native provider.');
        if ($options['state_authenticated'] ?? true) {
            $this->context->assert($state->setSamlAuthTrue(), 'Could not persist validated SAML authentication.');
        }
        $this->context->assert(
            $state->setPhase(LoginState::PHASE_GLPI_AUTH),
            'Could not persist the authenticated phase.'
        );
        if ($options['wrong_state_provider'] ?? false) {
            $other = $this->context->createProvider();
            $otherId = (int) $other->getDBFields()[ConfigEntity::ID];
            $this->context->assert($state->setIdpId($otherId), 'Could not set the mismatched persisted provider.');
        }
        if ($options['context'] ?? true) {
            $_SESSION['samlsso_slo_context'] = [
                'idp' => ($options['wrong_context_provider'] ?? false) ? $this->providerId + 1000 : $this->providerId,
                'name_id' => self::NAME_ID,
                'session_index' => self::SESSION_INDEX,
            ];
        }
        if (array_key_exists('logged_in', $options) && $options['logged_in'] === false) {
            \Session::cleanOnLogout();
            /** The subsequent anonymous request receives the core's normal session defaults. */
            \Session::initVars();
        }
        return $state;
    }

    /**
     * Populate the actual server globals consumed by php-saml and Symfony.
     *
     * @param array $options Forwarded origin and HTTP method variants.
     * @return void
     */
    public function requestEnvironment(array $options = []): void
    {
        $forwarded = $options['forwarded'] ?? false;
        unset($_SERVER['HTTP_X_FORWARDED_HOST'], $_SERVER['HTTP_X_FORWARDED_PROTO'], $_SERVER['HTTP_X_FORWARDED_PORT']);
        $_SERVER = array_replace($_SERVER, [
            'HTTP_HOST' => $forwarded ? 'backend.internal:8080' : 'sp.example.invalid',
            'SERVER_NAME' => $forwarded ? 'backend.internal' : 'sp.example.invalid',
            'SERVER_PORT' => $forwarded ? '8080' : '443',
            'HTTPS' => $forwarded ? 'off' : 'on',
            'SCRIPT_NAME' => '/index.php',
            'REQUEST_URI' => parse_url($this->callback, PHP_URL_PATH),
            'REQUEST_METHOD' => $options['method'] ?? 'GET',
        ]);
        if ($forwarded) {
            $_SERVER['HTTP_X_FORWARDED_HOST'] = 'sp.example.invalid';
            $_SERVER['HTTP_X_FORWARDED_PROTO'] = 'https';
            $_SERVER['HTTP_X_FORWARDED_PORT'] = '8443';
        }
    }

    /**
     * Build schema-valid logout XML with one optional field mutation.
     *
     * @param array $changes XML values to replace for negative cases.
     * @return string Serialized SAML LogoutRequest.
     */
    public function logoutXml(array $changes = []): string
    {
        $values = $changes + ['issuer' => self::IDP_ENTITY, 'destination' => $this->callback,
            'name' => self::NAME_ID, 'index' => self::SESSION_INDEX,
            'time' => gmdate('Y-m-d\TH:i:s\Z')];
        $document = new DOMDocument('1.0', 'UTF-8');
        $root = $document->createElementNS(Constants::NS_SAMLP, 'samlp:LogoutRequest');
        $document->appendChild($root);
        foreach (
            ['ID' => self::REQUEST_ID, 'Version' => '2.0', 'IssueInstant' => $values['time'],
                'Destination' => $values['destination']] as $name => $value
        ) {
            $root->setAttribute($name, $value);
        }
        foreach (['Issuer' => $values['issuer'], 'NameID' => $values['name']] as $name => $value) {
            $node = $document->createElementNS(Constants::NS_SAML, 'saml:' . $name);
            $node->appendChild($document->createTextNode($value));
            $root->appendChild($node);
        }
        $index = $document->createElementNS(Constants::NS_SAMLP, 'samlp:SessionIndex');
        $index->appendChild($document->createTextNode($values['index']));
        $root->appendChild($index);
        return $document->saveXML();
    }

    /**
     * Sign the exact HTTP-Redirect query bytes with the ephemeral IdP key.
     *
     * @param string $payload Base64-encoded, deflated XML or a deliberate invalid payload.
     * @param array $options Signature mutation options.
     * @return string Query ready for a real Symfony request.
     * @throws RuntimeException If OpenSSL signing fails.
     */
    public function logoutQuery(string $payload, array $options = []): string
    {
        $algorithm = array_key_exists('algorithm', $options) ? $options['algorithm'] : self::RSA_SHA256;
        $query = 'SAMLRequest=' . rawurlencode($payload) . '&RelayState=' . rawurlencode($this->relayState);
        if ($algorithm !== null) {
            $query .= '&SigAlg=' . rawurlencode($algorithm);
        }
        $opensslAlgorithm = match ($algorithm) {
            self::RSA_SHA1 => OPENSSL_ALGO_SHA1,
            self::RSA_SHA384 => OPENSSL_ALGO_SHA384,
            self::RSA_SHA512 => OPENSSL_ALGO_SHA512,
            default => OPENSSL_ALGO_SHA256,
        };
        $signature = '';
        $this->context->assert(
            openssl_sign($query, $signature, $this->idpKey, $opensslAlgorithm),
            'Cannot sign the native fixture.'
        );
        if ($options['tampered'] ?? false) {
            $query = str_replace(rawurlencode($this->relayState), 'changed', $query);
        }
        if ($options['array_algorithm'] ?? false) {
            $query = str_replace('&SigAlg=', '&SigAlg%5B0%5D=', $query);
        }
        if (!($options['unsigned'] ?? false)) {
            $query .= '&Signature=' . rawurlencode(base64_encode($signature));
        }
        return $query;
    }

    /**
     * Produce a genuine signed authentication response for the actual ACS toolkit.
     *
     * @param string $requestId Persisted AuthnRequest correlation.
     * @param string $nameId Native fixture username.
     * @param array $changes Deliberate response mutations before signing.
     * @return string Base64-encoded signed response.
     */
    public function authenticationResponse(string $requestId, string $nameId, array $changes = []): string
    {
        $escape = static fn(string $value): string => htmlspecialchars($value, ENT_QUOTES | ENT_XML1, 'UTF-8');
        $destination = $this->settings['sp']['assertionConsumerService']['url'];
        $responseId = $changes['id'] ?? '_native_response_' . bin2hex(random_bytes(8));
        $correlation = $changes['request'] ?? $requestId;
        $now = gmdate('Y-m-d\TH:i:s\Z');
        $before = gmdate('Y-m-d\TH:i:s\Z', time() - 60);
        $after = gmdate('Y-m-d\TH:i:s\Z', time() + 300);
        $assertion = '<saml:Assertion xmlns:saml="' . Constants::NS_SAML . '" ID="_assertion_'
            . bin2hex(random_bytes(8)) . '" Version="2.0" IssueInstant="' . $now . '">'
            . '<saml:Issuer>' . $escape(self::IDP_ENTITY) . '</saml:Issuer>'
            . '<saml:Subject><saml:NameID Format="' . Constants::NAMEID_UNSPECIFIED . '">'
            . $escape($nameId) . '</saml:NameID>'
            . '<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">'
            . '<saml:SubjectConfirmationData InResponseTo="' . $escape($correlation) . '" Recipient="'
            . $escape($destination) . '" NotOnOrAfter="' . $after . '"/>'
            . '</saml:SubjectConfirmation></saml:Subject>'
            . '<saml:Conditions NotBefore="' . $before . '" NotOnOrAfter="' . $after . '">'
            . '<saml:AudienceRestriction><saml:Audience>' . $escape($this->settings['sp']['entityId'])
            . '</saml:Audience></saml:AudienceRestriction></saml:Conditions>'
            . '<saml:AuthnStatement AuthnInstant="' . $now . '" SessionIndex="' . self::SESSION_INDEX . '">'
            . '<saml:AuthnContext><saml:AuthnContextClassRef>'
            . 'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport'
            . '</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement>'
            . '<saml:AttributeStatement><saml:Attribute '
            . 'Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress">'
            . '<saml:AttributeValue>' . $escape($nameId . '@example.invalid') . '</saml:AttributeValue>'
            . '</saml:Attribute></saml:AttributeStatement></saml:Assertion>';
        $signedAssertion = Utils::addSign($assertion, $this->idpPrivateKey, $this->idpCertificate);
        $assertionDocument = new DOMDocument();
        $this->context->assert($assertionDocument->loadXML($signedAssertion), 'Cannot parse the signed assertion.');
        /** The toolkit helper inserts assertion signatures before Issuer; the SAML schema requires them after it. */
        $signature = $assertionDocument->getElementsByTagNameNS(Constants::NS_DS, 'Signature')->item(0);
        $issuer = $assertionDocument->getElementsByTagNameNS(Constants::NS_SAML, 'Issuer')->item(0);
        $assertionDocument->documentElement->insertBefore($signature, $issuer->nextSibling);
        $response = '<samlp:Response xmlns:samlp="' . Constants::NS_SAMLP . '" xmlns:saml="' . Constants::NS_SAML
            . '" ID="' . $escape($responseId) . '" Version="2.0" IssueInstant="' . $now
            . '" Destination="' . $escape($destination) . '" InResponseTo="' . $escape($correlation) . '">'
            . '<saml:Issuer>' . $escape(self::IDP_ENTITY) . '</saml:Issuer>'
            . '<samlp:Status><samlp:StatusCode Value="' . Constants::STATUS_SUCCESS . '"/></samlp:Status>'
            . $assertionDocument->saveXML($assertionDocument->documentElement) . '</samlp:Response>';
        $signed = Utils::addSign($response, $this->idpPrivateKey, $this->idpCertificate);
        if ($changes['tampered'] ?? false) {
            $signed = str_replace($escape($nameId), 'tampered-subject', $signed);
        }
        return base64_encode($signed);
    }

    /**
     * Assert native logout, independent response verification, and failure atomicity.
     *
     * @param LoginState $state Persisted fixture state.
     * @param array $options Deliberate protocol mutations.
     * @param bool $accepted Expected protocol decision.
     * @return void
     */
    public function assertLogoutRequest(LoginState $state, array $options, bool $accepted): void
    {
        global $PLUGIN_HOOKS;

        $xml = $options['xml'] ?? [];
        if (isset($options['age'])) {
            $xml['time'] = gmdate('Y-m-d\TH:i:s\Z', time() + $options['age']);
        }
        $payload = $options['payload'] ?? base64_encode(gzdeflate($this->logoutXml($xml)));
        $query = $this->logoutQuery($payload, $options);
        parse_str($query, $_GET);
        $_SERVER['QUERY_STRING'] = $query;
        $_SERVER['REQUEST_URI'] = parse_url($this->callback, PHP_URL_PATH) . '?' . $query;
        $before = $_SESSION;
        $hookBefore = $PLUGIN_HOOKS[Hooks::PRE_ITEM_UPDATE] ?? null;
        $writeRejected = false;
        $rejectStateWrite = array_key_exists('phase_write', $options) && $options['phase_write'] === false;
        if ($rejectStateWrite) {
            $this->context->assert(\Plugin::isPluginActive('samlsso'), 'The native hook requires an active plugin.');
            $PLUGIN_HOOKS[Hooks::PRE_ITEM_UPDATE]['samlsso'][LoginState::class] =
                static function (\CommonDBTM $item) use ($state, &$writeRejected): void {
                    if (
                        (int) ($item->input[LoginState::STATE_ID] ?? 0) === $state->getStateId()
                        && (int) ($item->input[LoginState::PHASE] ?? 0) === LoginState::PHASE_LOGOFF
                    ) {
                        $writeRejected = true;
                        $item->input = false;
                    }
                };
        }
        try {
            $response = $this->invokeLogout($options);
        } finally {
            if ($hookBefore === null) {
                unset($PLUGIN_HOOKS[Hooks::PRE_ITEM_UPDATE]);
            } else {
                $PLUGIN_HOOKS[Hooks::PRE_ITEM_UPDATE] = $hookBefore;
            }
        }
        $this->context->same($accepted ? 302 : 400, $response->getStatusCode(), 'Unexpected native SLO status.');
        $row = $this->context->row(LoginState::getTable(), ['id' => $state->getStateId()]);
        $this->context->same(
            $accepted ? LoginState::PHASE_LOGOFF : LoginState::PHASE_GLPI_AUTH,
            (int) $row[LoginState::PHASE],
            'The persisted logout decision does not match the protocol outcome.'
        );
        if ($accepted) {
            $this->context->assert(empty($_SESSION['glpiID']), 'Native authentication survived logout.');
            $this->context->assert(!isset($_SESSION['samlsso_slo_context']), 'SAML correlation survived logout.');
            $this->assertLogoutResponse($response, $options['sign_response'] ?? false);
        } else {
            $this->context->assert($before === $_SESSION, 'Rejected logout altered the existing native session.');
            $this->context->assert(!$response instanceof RedirectResponse, 'Rejected logout redirected.');
        }
        if ($rejectStateWrite) {
            $this->context->assert(
                $writeRejected,
                'The native pre-update hook did not exercise a rejected state write.'
            );
        }
    }

    /**
     * Call the production controller and verify scoped XML and proxy settings.
     *
     * @param array $options Initial toolkit and XML modes.
     * @return Response Actual Symfony response from the native controller.
     */
    public function invokeLogout(array $options = []): Response
    {
        $originalXml = libxml_use_internal_errors();
        $originalProxy = Utils::getProxyVars();
        $xml = $options['xml_errors'] ?? false;
        $proxy = $options['initial_proxy'] ?? false;
        libxml_clear_errors();
        libxml_use_internal_errors($xml);
        Utils::setProxyVars($proxy);
        try {
            $request = new Request($_GET, $_POST, [LoginState::IDP_ID => $this->providerId], [], [], $_SERVER);
            $response = (new SamlSsoController())->slo($request);
            $this->context->assert(
                $response->headers->hasCacheControlDirective('no-store'),
                'SLO response must not be cached.'
            );
            $this->context->same($xml, libxml_use_internal_errors(), 'SLO changed the XML diagnostic mode.');
            $this->context->same([], libxml_get_errors(), 'SLO retained XML parser diagnostics.');
            $this->context->same($proxy, Utils::getProxyVars(), 'SLO changed proxy trust outside the request.');
            return $response;
        } finally {
            libxml_clear_errors();
            libxml_use_internal_errors($originalXml);
            Utils::setProxyVars($originalProxy);
        }
    }

    /**
     * Verify the response XML and signature without delegating validation to the producer.
     *
     * @param Response $response Controller result.
     * @param bool $signed Whether this provider enables signed logout responses.
     * @return void
     */
    private function assertLogoutResponse(Response $response, bool $signed): void
    {
        if (!$response instanceof RedirectResponse) {
            throw new RuntimeException('Accepted logout did not redirect.');
        }
        $parts = parse_url($response->getTargetUrl());
        $this->context->same(
            self::IDP_LOGOUT,
            ($parts['scheme'] ?? '') . '://' . ($parts['host'] ?? '') . ($parts['path'] ?? ''),
            'Response targeted a different IdP.'
        );
        parse_str($parts['query'] ?? '', $query);
        $this->context->same($this->relayState, $query['RelayState'] ?? '', 'Response lost RelayState.');
        $decoded = base64_decode($query['SAMLResponse'] ?? '', true);
        $this->context->assert($decoded !== false, 'Response payload is not base64.');
        $xml = gzinflate($decoded);
        $this->context->assert(is_string($xml), 'Response payload is not deflated XML.');
        $document = new DOMDocument();
        $this->context->assert($document->loadXML($xml, LIBXML_NONET), 'Response is invalid XML.');
        $root = $document->documentElement;
        $this->context->same('LogoutResponse', $root->localName, 'Response has the wrong protocol element.');
        $this->context->same(Constants::NS_SAMLP, $root->namespaceURI, 'Response has the wrong namespace.');
        $this->context->same(
            self::REQUEST_ID,
            $root->getAttribute('InResponseTo'),
            'Response lost request correlation.'
        );
        $this->context->same(
            self::IDP_LOGOUT,
            $root->getAttribute('Destination'),
            'Response has the wrong destination.'
        );
        $issuer = $document->getElementsByTagNameNS(Constants::NS_SAML, 'Issuer')->item(0);
        $this->context->same(
            $this->settings['sp']['entityId'],
            $issuer?->textContent,
            'Response has the wrong issuer.'
        );
        $status = $document->getElementsByTagNameNS(Constants::NS_SAMLP, 'StatusCode')->item(0);
        $this->context->same(
            Constants::STATUS_SUCCESS,
            $status?->getAttribute('Value'),
            'Response status is not Success.'
        );
        if (!$signed) {
            $this->context->assert(!isset($query['Signature']), 'Response ignored the disabled signing setting.');
            return;
        }
        $this->context->same(self::RSA_SHA256, $query['SigAlg'] ?? '', 'Unexpected response signing algorithm.');
        $encoded = [];
        foreach (explode('&', $parts['query']) as $parameter) {
            [$name, $value] = explode('=', $parameter, 2);
            $encoded[$name] = $value;
        }
        $signedQuery = 'SAMLResponse=' . $encoded['SAMLResponse']
            . '&RelayState=' . $encoded['RelayState'] . '&SigAlg=' . $encoded['SigAlg'];
        $signature = base64_decode($query['Signature'] ?? '', true);
        $this->context->assert(
            $signature !== false
            && openssl_verify($signedQuery, $signature, $this->spCertificate, OPENSSL_ALGO_SHA256) === 1,
            'Response signature does not verify with the independent SP certificate.'
        );
    }

    /**
     * Generate a short-lived certificate without retaining private material on disk.
     *
     * @param string $commonName Public fixture subject.
     * @return array{OpenSSLAsymmetricKey, string, string} Key object, certificate and private PEM.
     * @throws RuntimeException If certificate generation fails.
     */
    private function certificate(string $commonName): array
    {
        $key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        $this->context->assert($key !== false, 'Cannot create the ephemeral RSA key.');
        $csr = openssl_csr_new(['commonName' => $commonName], $key, ['digest_alg' => 'sha256']);
        $this->context->assert($csr !== false, 'Cannot create the ephemeral CSR.');
        $certificate = openssl_csr_sign($csr, null, $key, 2, ['digest_alg' => 'sha256']);
        $pem = $private = '';
        $this->context->assert(
            $certificate !== false && openssl_x509_export($certificate, $pem),
            'Cannot export the certificate.'
        );
        $this->context->assert(openssl_pkey_export($key, $private), 'Cannot export the signing key.');
        return [$key, $pem, $private];
    }
}
