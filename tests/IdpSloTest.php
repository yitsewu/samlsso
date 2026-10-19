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

/** Standalone boundary doubles must share one process; production classes remain one per file. */
// phpcs:disable PSR1.Classes.ClassDeclaration.MultipleClasses

namespace Symfony\Component\HttpFoundation {
    /** Store route parameters at the HTTP boundary without loading the GLPI kernel. */
    class ParameterBag
    {
        private array $data = [];

        /** Assign a route parameter used by the controller. */
        public function set(string $key, mixed $value): void
        {
            $this->data[$key] = $value;
        }

        /** Return a route parameter or the supplied fallback. */
        public function get(string $key, mixed $default = null): mixed
        {
            return $this->data[$key] ?? $default;
        }
    }

    /** Provide only the route attributes and HTTP method consumed by the SLO controller. */
    class Request
    {
        public ParameterBag $attributes;

        /** Initialize an independent attribute bag for each request. */
        public function __construct(private string $method = 'GET')
        {
            $this->attributes = new ParameterBag();
        }

        /** Compare the fixture method using Symfony's case-insensitive contract. */
        public function isMethod(string $method): bool
        {
            return strtoupper($this->method) === strtoupper($method);
        }
    }

    /** Retain the response body, status and headers for assertions. */
    class Response
    {
        public function __construct(
            public string $content = '',
            private int $status = 200,
            public array $headers = []
        ) {
        }

        /** Expose the status code without requiring the real HTTP kernel. */
        public function getStatusCode(): int
        {
            return $this->status;
        }
    }

    /** Model a redirect's target URL separately from an HTML response body. */
    class RedirectResponse extends Response
    {
        /** Preserve Symfony's default redirect status and target URL. */
        public function __construct(
            private string $targetUrl,
            int $status = 302,
            array $headers = []
        ) {
            parent::__construct('', $status, $headers);
        }

        /** Return the generated protocol redirect for independent verification. */
        public function getTargetUrl(): string
        {
            return $this->targetUrl;
        }
    }
}

namespace Glpi\Controller {
    /** Stand in for the controller base; no GLPI framework behavior is simulated. */
    abstract class AbstractController
    {
    }
}

namespace Glpi\Application\View {
    /** Verify the completion page selection without pretending to execute Twig. */
    class TemplateRenderer
    {
        public static array $renders = [];

        /** Supply the same entry point as the native renderer. */
        public static function getInstance(): self
        {
            return new self();
        }

        /** Record the template and variables and return a recognizable fixture body. */
        public function render(string $template, array $variables): string
        {
            self::$renders[] = [$template, $variables];
            return 'fixture completion page';
        }
    }
}

namespace GlpiPlugin\Samlsso {
    /** Model only state lookup and mutation; the real toolkit performs protocol validation. */
    class LoginState
    {
        public const IDP_ID = 'idpId';
        public const PHASE_LOGOFF = 8;
        public static int $providerId = 1;
        public static bool $authenticated = true;
        public static array $events = [];

        /** Return the provider associated with the current fixture login. */
        public function getIdpId(): int
        {
            return self::$providerId;
        }

        /** Report whether the existing login has passed SAML authentication. */
        public function isSamlAuthed(): bool
        {
            return self::$authenticated;
        }

        /** Record state mutation so its ordering relative to cleanup can be asserted. */
        public function setPhase(int $phase): void
        {
            self::$events[] = 'phase:' . $phase;
        }
    }
}

namespace GlpiPlugin\Samlsso\Config {
    /** Keep provider configuration deterministic while using the real php-saml settings object. */
    class ConfigEntity
    {
        public const PROXIED = 'proxied';
        public static array $settings = [];
        public static bool $proxied = false;
        public static bool $active = true;

        /** Reject provider IDs not present in the local fixture. */
        public function __construct(int $id)
        {
            if ($id !== 1) {
                throw new \UnexpectedValueException('Unknown fixture provider');
            }
        }

        /** The fixture configuration itself is valid independently of its enabled state. */
        public function isValid(): bool
        {
            return true;
        }

        /** Allow rejection tests to disable the provider. */
        public function isActive(): bool
        {
            return self::$active;
        }

        /** Supply the exact php-saml settings used to sign and verify this request. */
        public function getPhpSamlConfig(): array
        {
            return self::$settings;
        }

        /** Expose the provider's proxy trust decision using the native field name. */
        public function getField(string $field): bool
        {
            return $field === self::PROXIED && self::$proxied;
        }
    }
}

namespace {
    use Glpi\Application\View\TemplateRenderer;
    use GlpiPlugin\Samlsso\Config\ConfigEntity;
    use GlpiPlugin\Samlsso\Controller\SamlSsoController;
    use GlpiPlugin\Samlsso\LoginState;
    use OneLogin\Saml2\Constants;
    use OneLogin\Saml2\Utils;
    use Symfony\Component\HttpFoundation\RedirectResponse;
    use Symfony\Component\HttpFoundation\Request;
    use Symfony\Component\HttpFoundation\Response;

    /** Expose cleanup as an observable boundary without destroying the test process session. */
    class Session
    {
        /** Record cleanup after any state transition and remove the current fixture login. */
        public static function cleanOnLogout(): void
        {
            LoginState::$events[] = 'cleanup';
            $_SESSION = [];
        }
    }

    /** Capture native page wrapping used by the inert completion response. */
    class Html
    {
        public static array $calls = [];

        /** Record the page header without producing output in the CLI runner. */
        public static function nullHeader(string $title = '', mixed ...$options): void
        {
            self::$calls[] = 'header';
        }

        /** Record the page footer without producing output in the CLI runner. */
        public static function nullFooter(): void
        {
            self::$calls[] = 'footer';
        }
    }

    /** Preserve translated message text at the fixture boundary. */
    function __(string $message, string $domain = ''): string
    {
        return $message;
    }

    define('PLUGIN_NAME', 'samlsso');
    require_once __DIR__ . '/../vendor/autoload.php';
    require_once __DIR__ . '/../src/Controller/SamlSsoController.php';

    /**
     * Exercise signed HTTP-Redirect requests against the real bundled toolkit.
     * Identities are fictional and independent IdP/SP signing keys exist only in memory.
     */
    final class IdpSloTest
    {
        private const SP_ENTITY = 'https://sp.example.test/';
        private const IDP_ENTITY = 'https://idp.example.test/metadata';
        private const IDP_LOGOUT = 'https://idp.example.test/slo';
        private const CALLBACK_PATH = '/plugins/samlsso/front/logout/1';
        private const REQUEST_ID = '_fixture_logout_request';
        private const RELAY_STATE = 'fixture-return & value';
        private const RSA_SHA256 = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';
        private const RSA_SHA384 = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha384';
        private const RSA_SHA512 = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512';
        private const RSA_SHA1 = 'http://www.w3.org/2000/09/xmldsig#rsa-sha1';

        private OpenSSLAsymmetricKey $idpKey;
        private string $idpCertificate;
        private string $spPrivateKey;
        private string $spCertificate;
        private int $passed = 0;

        /** Generate separate certificates so returned signatures cannot be checked against the wrong party. */
        public function __construct()
        {
            [$this->idpKey, $this->idpCertificate] = $this->createCertificate('idp-fixture.invalid');
            [$spKey, $this->spCertificate] = $this->createCertificate('sp-fixture.invalid');
            if (!openssl_pkey_export($spKey, $privateKey)) {
                throw new UnexpectedValueException('Could not export the ephemeral SP signing key');
            }
            $this->spPrivateKey = $privateKey;
        }

        /**
         * Generate an in-memory RSA key and short-lived self-signed fixture certificate.
         *
         * @return array{OpenSSLAsymmetricKey, string}
         * @throws UnexpectedValueException when OpenSSL cannot create the fixture.
         */
        private function createCertificate(string $commonName): array
        {
            $key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
            if ($key === false) {
                throw new UnexpectedValueException('Could not create an ephemeral signing key');
            }
            $request = openssl_csr_new(['commonName' => $commonName], $key, ['digest_alg' => 'sha256']);
            $certificate = $request === false
                ? false
                : openssl_csr_sign($request, null, $key, 1, ['digest_alg' => 'sha256']);
            if ($certificate === false || !openssl_x509_export($certificate, $pem)) {
                throw new UnexpectedValueException('Could not create an ephemeral signing certificate');
            }
            return [$key, $pem];
        }

        /** Run protocol, mutation, proxy, parser and inert-completion cases independently. */
        public function run(): void
        {
            $this->assertStateConstantMatchesProduction();
            $this->assertRequest('valid', [], true);
            $this->assertRequest('signed_response', ['sign_response' => true], true);
            $this->assertRequest('rsa_sha384', ['algorithm' => self::RSA_SHA384], true);
            $this->assertRequest('rsa_sha512', ['algorithm' => self::RSA_SHA512], true);
            $this->assertRequest('proxied', ['forwarded' => true, 'proxied' => true], true);
            $this->assertRequest('proxy_state_restored', ['initial_proxy' => true], true);
            $this->assertRequest('valid_xml_mode_restored', ['xml_errors' => true], true);

            $rejections = [
                'unsigned' => ['unsigned' => true],
                'tampered_relay' => ['tampered' => true],
                'wrong_name' => ['xml' => ['name' => 'another-user']],
                'wrong_index' => ['xml' => ['index' => 'another-session']],
                'wrong_issuer' => ['xml' => ['issuer' => 'https://other.example.test/metadata']],
                'wrong_destination' => ['xml' => ['destination' => 'https://other.example.test/logout']],
                'expired' => ['xml' => ['time' => gmdate('Y-m-d\TH:i:s\Z', time() - 600)]],
                'future' => ['xml' => ['time' => gmdate('Y-m-d\TH:i:s\Z', time() + 600)]],
                'missing_context' => ['context' => false],
                'logged_out_request' => ['logged_in' => false],
                'wrong_context_provider' => ['context_provider' => 2],
                'wrong_state_provider' => ['state_provider' => 2],
                'unauthenticated_state' => ['state_authenticated' => false],
                'disabled_provider' => ['active' => false],
                'forwarded_without_trust' => ['forwarded' => true],
                'forwarded_without_trust_restored' => ['forwarded' => true, 'initial_proxy' => true],
                'sha1' => ['algorithm' => self::RSA_SHA1],
                'missing_algorithm' => ['algorithm' => null],
                'empty_algorithm' => ['algorithm' => ''],
                'unknown_algorithm' => ['algorithm' => 'urn:fixture:unknown-algorithm'],
                'array_algorithm' => ['array_algorithm' => true],
                'post_request' => ['method' => 'POST'],
            ];
            foreach ($rejections as $name => $options) {
                $this->assertRequest($name, $options, false);
            }
            foreach ([false, true] as $internalErrors) {
                $this->assertRequest('malformed_payload_' . (int) $internalErrors, [
                    'payload' => 'invalid',
                    'xml_errors' => $internalErrors,
                ], false);
                $this->assertRequest('truncated_xml_' . (int) $internalErrors, [
                    'payload' => base64_encode(gzdeflate('<broken')),
                    'xml_errors' => $internalErrors,
                ], false);
            }
            $this->assertCompletion('bare_logged_out', [], false);
            $this->assertCompletion('response_logged_out', ['SAMLResponse' => 'untrusted-fixture'], false);
            $this->assertCompletion('bare_logged_in', [], true);
            $this->assertCompletion('response_logged_in', ['SAMLResponse' => 'untrusted-fixture'], true);
            echo "✅ IdP SLO: {$this->passed} protocol and completion cases passed\n";
        }

        /** Fail if the boundary double diverges from the production terminal phase constant. */
        private function assertStateConstantMatchesProduction(): void
        {
            $source = file_get_contents(__DIR__ . '/../src/LoginState.php');
            $matched = preg_match('/public const PHASE_LOGOFF\s*=\s*(\d+)\s*;/', $source, $match);
            $this->expect(
                $matched === 1 && (int) $match[1] === LoginState::PHASE_LOGOFF,
                'The LoginState fixture must track the production PHASE_LOGOFF constant'
            );
        }

        /** Configure independent provider settings and reset all observable request boundaries. */
        private function reset(array $options): string
        {
            $forwarded = $options['forwarded'] ?? false;
            $origin = $forwarded ? 'https://sp.example.test:8443' : 'https://sp.example.test';
            $callback = $origin . self::CALLBACK_PATH;
            ConfigEntity::$proxied = $options['proxied'] ?? false;
            ConfigEntity::$active = $options['active'] ?? true;
            ConfigEntity::$settings = [
                'strict' => true,
                'debug' => false,
                'sp' => [
                    'entityId' => self::SP_ENTITY,
                    'assertionConsumerService' => ['url' => $origin . '/acs'],
                    'singleLogoutService' => ['url' => $callback],
                    'privateKey' => $this->spPrivateKey,
                    'x509cert' => $this->spCertificate,
                ],
                'idp' => [
                    'entityId' => self::IDP_ENTITY,
                    'singleSignOnService' => ['url' => 'https://idp.example.test/sso'],
                    'singleLogoutService' => ['url' => self::IDP_LOGOUT],
                    'x509cert' => $this->idpCertificate,
                ],
                'security' => [
                    'wantMessagesSigned' => true,
                    'logoutResponseSigned' => $options['sign_response'] ?? false,
                    'signatureAlgorithm' => self::RSA_SHA256,
                ],
            ];
            LoginState::$providerId = $options['state_provider'] ?? 1;
            LoginState::$authenticated = $options['state_authenticated'] ?? true;
            LoginState::$events = [];
            TemplateRenderer::$renders = [];
            Html::$calls = [];
            $GLOBALS['CFG_GLPI'] = ['root_doc' => '', 'url_base' => $origin];
            $_GET = [];
            $_POST = [];
            $_SESSION = ($options['logged_in'] ?? true) ? ['glpiID' => 8, 'fixture_marker' => 'preserved'] : [];
            if ($options['context'] ?? true) {
                $_SESSION['samlsso_slo_context'] = [
                    'idp' => $options['context_provider'] ?? 1,
                    'name_id' => 'fixture-owner',
                    'session_index' => 'fixture-session',
                ];
            }
            $_SERVER = [
                'HTTP_HOST' => $forwarded ? 'backend.internal:8080' : 'sp.example.test',
                'SERVER_NAME' => $forwarded ? 'backend.internal' : 'sp.example.test',
                'SERVER_PORT' => $forwarded ? '8080' : '443',
                'HTTPS' => $forwarded ? 'off' : 'on',
                'SCRIPT_NAME' => '/index.php',
                'REQUEST_URI' => self::CALLBACK_PATH,
                'REQUEST_METHOD' => $options['method'] ?? 'GET',
            ];
            if ($forwarded) {
                $_SERVER['HTTP_X_FORWARDED_HOST'] = 'sp.example.test';
                $_SERVER['HTTP_X_FORWARDED_PROTO'] = 'https';
                $_SERVER['HTTP_X_FORWARDED_PORT'] = '8443';
            }
            return $callback;
        }

        /** Build well-formed protocol XML while allowing one field at a time to violate its contract. */
        private function buildRequestXml(string $callback, array $changes): string
        {
            $values = array_replace([
                'issuer' => self::IDP_ENTITY,
                'destination' => $callback,
                'name' => 'fixture-owner',
                'index' => 'fixture-session',
                'time' => gmdate('Y-m-d\TH:i:s\Z'),
            ], $changes);
            $document = new DOMDocument('1.0', 'UTF-8');
            $root = $document->createElementNS(Constants::NS_SAMLP, 'samlp:LogoutRequest');
            $document->appendChild($root);
            $attributes = [
                'ID' => self::REQUEST_ID,
                'Version' => '2.0',
                'IssueInstant' => $values['time'],
                'Destination' => $values['destination'],
            ];
            foreach ($attributes as $attribute => $value) {
                $root->setAttribute($attribute, $value);
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

        /** Sign the exact Redirect query bytes, including deliberately weak or unrecognized algorithm labels. */
        private function buildQuery(string $payload, array $options): string
        {
            $algorithm = array_key_exists('algorithm', $options) ? $options['algorithm'] : self::RSA_SHA256;
            $query = 'SAMLRequest=' . rawurlencode($payload) . '&RelayState=' . rawurlencode(self::RELAY_STATE);
            if ($algorithm !== null) {
                $query .= '&SigAlg=' . rawurlencode($algorithm);
            }
            $opensslAlgorithm = match ($algorithm) {
                self::RSA_SHA1 => OPENSSL_ALGO_SHA1,
                self::RSA_SHA384 => OPENSSL_ALGO_SHA384,
                self::RSA_SHA512 => OPENSSL_ALGO_SHA512,
                default => OPENSSL_ALGO_SHA256,
            };
            $this->expect(openssl_sign($query, $signature, $this->idpKey, $opensslAlgorithm), 'Fixture signing failed');
            if ($options['tampered'] ?? false) {
                $query = str_replace(rawurlencode(self::RELAY_STATE), 'changed', $query);
            }
            if ($options['array_algorithm'] ?? false) {
                $query = str_replace('&SigAlg=', '&SigAlg%5B0%5D=', $query);
            }
            if (!($options['unsigned'] ?? false)) {
                $query .= '&Signature=' . rawurlencode(base64_encode($signature));
            }
            return $query;
        }

        /** Assert an accepted request's response and cleanup, or an entirely inert rejection. */
        private function assertRequest(string $name, array $options, bool $accepted): void
        {
            $callback = $this->reset($options);
            $payload = $options['payload']
                ?? base64_encode(gzdeflate($this->buildRequestXml($callback, $options['xml'] ?? [])));
            $query = $this->buildQuery($payload, $options);
            parse_str($query, $_GET);
            $_SERVER['QUERY_STRING'] = $query;
            $_SERVER['REQUEST_URI'] = self::CALLBACK_PATH . '?' . $query;
            $sessionBefore = $_SESSION;
            $response = $this->invoke($options);
            $this->expect($response->getStatusCode() === ($accepted ? 302 : 400), $name . ': unexpected HTTP status');
            $this->expect(($response->headers['Cache-Control'] ?? '') === 'no-store', $name . ': missing no-store');
            if ($accepted) {
                $this->expect(LoginState::$events === ['phase:8', 'cleanup'], $name . ': incorrect cleanup ordering');
                $this->expect($_SESSION === [], $name . ': authenticated context survived cleanup');
                $this->assertLogoutResponse($response, $options['sign_response'] ?? false);
            } else {
                $this->expect(LoginState::$events === [], $name . ': rejected request mutated login state');
                $this->expect($_SESSION === $sessionBefore, $name . ': rejected request altered the session');
            }
            $this->passed++;
        }

        /** Verify a logged-out completion renders only a local status page and never consumes untrusted SAML data. */
        private function assertCompletion(string $name, array $query, bool $loggedIn): void
        {
            $this->reset(['logged_in' => $loggedIn, 'context' => false]);
            $_GET = $query;
            $_SERVER['QUERY_STRING'] = http_build_query($query);
            $sessionBefore = $_SESSION;
            $response = $this->invoke([]);
            $this->expect($response->getStatusCode() === ($loggedIn ? 400 : 200), $name . ': wrong completion status');
            $this->expect(($response->headers['Cache-Control'] ?? '') === 'no-store', $name . ': missing no-store');
            $this->expect(LoginState::$events === [], $name . ': completion performed logout');
            $this->expect($_SESSION === $sessionBefore, $name . ': completion changed the existing session');
            if ($loggedIn) {
                $this->expect(TemplateRenderer::$renders === [], $name . ': active login received a success page');
            } else {
                $this->expect(count(TemplateRenderer::$renders) === 1, $name . ': completion was not rendered');
                [$template, $variables] = TemplateRenderer::$renders[0];
                $this->expect($template === '@samlsso/loggedOut.html.twig', $name . ': wrong completion template');
                $this->expect(isset($variables['loginPath']), $name . ': missing local sign-in link');
                $this->expect(Html::$calls === ['header', 'footer'], $name . ': native page wrapping missing');
            }
            $this->passed++;
        }

        /**
         * Invoke the real controller and assert request-global XML/proxy settings are restored.
         * PHP diagnostics fail the case, except operations deliberately silenced by the toolkit.
         */
        private function invoke(array $options): Response
        {
            $originalXmlMode = libxml_use_internal_errors();
            $originalProxyMode = Utils::getProxyVars();
            $xmlMode = $options['xml_errors'] ?? false;
            $proxyMode = $options['initial_proxy'] ?? false;
            libxml_clear_errors();
            libxml_use_internal_errors($xmlMode);
            Utils::setProxyVars($proxyMode);
            $warnings = [];
            set_error_handler(static function (int $severity, string $message) use (&$warnings): bool {
                if (error_reporting() & $severity) {
                    $warnings[] = $message;
                }
                return true;
            });
            try {
                $request = new Request($options['method'] ?? 'GET');
                $request->attributes->set(LoginState::IDP_ID, 1);
                $response = (new SamlSsoController())->slo($request);
                $this->expect($warnings === [], 'Controller emitted PHP diagnostics: ' . implode('; ', $warnings));
                $this->expect(libxml_use_internal_errors() === $xmlMode, 'Controller changed libxml error mode');
                $this->expect(libxml_get_errors() === [], 'Controller retained libxml diagnostics');
                $this->expect(Utils::getProxyVars() === $proxyMode, 'Controller changed toolkit proxy trust mode');
                return $response;
            } finally {
                restore_error_handler();
                libxml_clear_errors();
                libxml_use_internal_errors($originalXmlMode);
                Utils::setProxyVars($originalProxyMode);
            }
        }

        /** Independently inspect the returned protocol response, rather than accepting any redirect as success. */
        private function assertLogoutResponse(Response $response, bool $signed): void
        {
            $this->expect($response instanceof RedirectResponse, 'Successful SLO did not return a redirect');
            $target = $response->getTargetUrl();
            $parts = parse_url($target);
            $this->expect(
                ($parts['scheme'] ?? '') . '://' . ($parts['host'] ?? '') . ($parts['path'] ?? '') === self::IDP_LOGOUT,
                'LogoutResponse did not target the configured IdP'
            );
            parse_str($parts['query'] ?? '', $query);
            $this->expect(($query['RelayState'] ?? '') === self::RELAY_STATE, 'Response lost the signed RelayState');
            $decoded = base64_decode($query['SAMLResponse'] ?? '', true);
            $this->expect($decoded !== false, 'Response is not valid base64');
            $xml = gzinflate($decoded);
            $this->expect(is_string($xml), 'Response is not deflated SAML');
            $document = new DOMDocument();
            $this->expect($document->loadXML($xml, LIBXML_NONET), 'Response is not valid XML');
            $root = $document->documentElement;
            $this->expect(
                $root->localName === 'LogoutResponse' && $root->namespaceURI === Constants::NS_SAMLP,
                'Response has the wrong protocol root'
            );
            $this->expect($root->getAttribute('InResponseTo') === self::REQUEST_ID, 'Response correlation is missing');
            $this->expect($root->getAttribute('Destination') === self::IDP_LOGOUT, 'Response destination is wrong');
            $issuer = $document->getElementsByTagNameNS(Constants::NS_SAML, 'Issuer')->item(0);
            $this->expect($issuer?->textContent === self::SP_ENTITY, 'Response issuer is wrong');
            $status = $document->getElementsByTagNameNS(Constants::NS_SAMLP, 'StatusCode')->item(0);
            $this->expect($status?->getAttribute('Value') === Constants::STATUS_SUCCESS, 'Response is not successful');
            if ($signed) {
                $this->expect(($query['SigAlg'] ?? '') === self::RSA_SHA256, 'Response signature algorithm is wrong');
                /** Verify the exact wire encoding, including '+' versus '%20' in RelayState. */
                $encodedFields = [];
                foreach (explode('&', $parts['query']) as $parameter) {
                    [$name, $value] = explode('=', $parameter, 2);
                    $encodedFields[$name] = $value;
                }
                $signedQuery = 'SAMLResponse=' . $encodedFields['SAMLResponse']
                    . '&RelayState=' . $encodedFields['RelayState']
                    . '&SigAlg=' . $encodedFields['SigAlg'];
                $signature = base64_decode($query['Signature'] ?? '', true);
                $this->expect(
                    $signature !== false
                    && openssl_verify($signedQuery, $signature, $this->spCertificate, OPENSSL_ALGO_SHA256) === 1,
                    'Response signature does not verify with the SP certificate'
                );
            } else {
                $this->expect(!isset($query['Signature']), 'Response signing ignored the disabled fixture setting');
            }
        }

        /** Fail immediately with the exact violated fixture contract. */
        private function expect(bool $condition, string $message): void
        {
            if (!$condition) {
                throw new UnexpectedValueException($message);
            }
        }
    }

    try {
        (new IdpSloTest())->run();
    } catch (Throwable $error) {
        fwrite(STDERR, 'IdP SLO test failed: ' . $error->getMessage() . "\n");
        exit(1);
    }
}
