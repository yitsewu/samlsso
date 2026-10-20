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
use GlpiPlugin\Samlsso\Config\ConfigEntity;
use GlpiPlugin\Samlsso\LoginState;
use OneLogin\Saml2\Constants;
use OneLogin\Saml2\Utils;
use RuntimeException;

/** Fixture data never substitutes for a GLPI, plugin, or toolkit implementation. */
final class ProtocolFixtures
{
    public const IDP_ENTITY = 'https://idp.example.invalid/metadata';
    public const IDP_LOGOUT = 'https://idp.example.invalid/logout';
    public const SESSION_INDEX = '_native-fixture-session';

    public readonly ConfigEntity $provider;
    public readonly int $providerId;
    public readonly array $settings;
    public readonly string $callback;
    public readonly string $idpCertificate;
    public readonly string $idpPrivateKey;
    public readonly string $spCertificate;

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

        [, $this->idpCertificate, $this->idpPrivateKey] = $this->certificate('idp.example.invalid');
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
     * Generate a short-lived certificate without retaining private material on disk.
     *
     * @param string $commonName Public fixture subject.
     * @return array{\OpenSSLAsymmetricKey, string, string} Key object, certificate and private PEM.
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
