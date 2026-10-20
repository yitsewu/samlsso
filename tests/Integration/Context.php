<?php

/**
 * Assertions and fixture creation through the real GLPI framework.
 *
 * @package samlSSO
 * @version 1.3.2
 * @copyright Copyright (c) 2024 by Chris Gralike
 * @license GPLv3+
 */

declare(strict_types=1);

namespace GlpiPlugin\Samlsso\Tests\Integration;

use GlpiPlugin\Samlsso\Config;
use GlpiPlugin\Samlsso\Config\ConfigDefaultTpl;
use GlpiPlugin\Samlsso\Config\ConfigEntity;
use RuntimeException;

/** Test helpers never subclass or replace a GLPI core class. */
final class Context
{
    private array $baseline = [];
    private bool $transaction = false;
    private ?array $certificate = null;

    /**
     * Retain the verified framework and plugin locations without replacing any native implementation.
     *
     * @param string $runtime Absolute path of the booted GLPI installation.
     * @param string $pluginRoot Absolute path of the checkout being tested.
     */
    public function __construct(public readonly string $runtime, public readonly string $pluginRoot)
    {
    }

    /**
     * Return the framework's own connection, without a database adapter or double.
     *
     * @return \DBmysql The real connection initialized by the selected GLPI runtime.
     */
    public function db(): \DBmysql
    {
        global $DB;
        return $DB;
    }

    /**
     * Isolate each case's data and request state. DDL belongs to Provision.php.
     *
     * @return void
     * @throws \Throwable When native session, translation, or transaction initialization fails.
     */
    public function begin(): void
    {
        global $CFG_GLPI;
        $this->baseline = [$_GET, $_POST, $_REQUEST, $_COOKIE, $_SERVER, $_SESSION ?? [], $CFG_GLPI];
        $_GET = $_POST = $_REQUEST = $_COOKIE = [];
        $_SESSION = [];
        if (session_status() !== PHP_SESSION_ACTIVE) {
            session_id('samlsso-test-' . bin2hex(random_bytes(12)));
            session_start();
        }
        \Session::initVars();
        \Session::loadLanguage('en_GB');
        $this->db()->beginTransaction();
        $this->transaction = true;
    }

    /**
     * Roll back even when an assertion throws; restore actual request state afterward.
     *
     * @return void
     * @throws \Throwable When the native database rollback fails.
     */
    public function rollback(): void
    {
        global $CFG_GLPI;
        if ($this->transaction) {
            $this->db()->rollBack();
            $this->transaction = false;
        }
        [$_GET, $_POST, $_REQUEST, $_COOKIE, $_SERVER, $_SESSION, $CFG_GLPI] = $this->baseline;
    }

    /**
     * Fail the current case when an observed condition is false.
     *
     * @param bool $condition Actual assertion result.
     * @param string $message Diagnostic explaining the violated contract, without secret values.
     * @return void
     * @throws RuntimeException When the assertion fails.
     */
    public function assert(bool $condition, string $message): void
    {
        if (!$condition) {
            throw new RuntimeException($message);
        }
    }

    /**
     * Compare non-secret fixture values with strict identity.
     *
     * @param mixed $expected Expected non-secret value.
     * @param mixed $actual Observed non-secret value.
     * @param string $message Diagnostic explaining the expected contract.
     * @return void
     * @throws RuntimeException When values or their types differ.
     */
    public function same(mixed $expected, mixed $actual, string $message): void
    {
        if ($expected !== $actual) {
            throw new RuntimeException($message . ' Expected ' . var_export($expected, true)
                . ', received ' . var_export($actual, true));
        }
    }

    /**
     * Read persisted fixture rows using the actual GLPI query builder.
     *
     * @param string $table Native table name.
     * @param array $where Native query conditions.
     * @return array Matching rows in database iteration order.
     */
    public function rows(string $table, array $where): array
    {
        return iterator_to_array($this->db()->request(['FROM' => $table, 'WHERE' => $where]), false);
    }

    /**
     * Read exactly one persisted fixture row.
     *
     * @param string $table Native table name.
     * @param array $where Native query conditions identifying one record.
     * @return array The single matching database row.
     * @throws RuntimeException When the query matches zero or multiple records.
     */
    public function row(string $table, array $where): array
    {
        $rows = $this->rows($table, $where);
        $this->same(1, count($rows), 'Expected exactly one persisted row in ' . $table);
        return $rows[0];
    }

    /**
     * Create a local fixture account and a real profile relation without sending mail.
     *
     * @param array $extra Native User::add values overriding the safe fixture defaults.
     * @return \User The reloaded native account with an administrator profile relation.
     * @throws RuntimeException When account creation or native relation persistence fails.
     */
    public function createUser(array $extra = []): \User
    {
        $name = 'samlsso_test_' . bin2hex(random_bytes(8));
        $user = new \User();
        $id = $user->add($extra + [
            'name' => $name,
            'realname' => 'Integration',
            'firstname' => 'Fixture',
            '_useremails' => [$name . '@example.invalid'],
            'is_active' => 1,
            'authtype' => \Auth::DB_GLPI,
            '_notifications' => 0,
        ]);
        $this->assert(is_int($id) && $id > 0, 'Native User::add failed.');
        $profiles = $this->rows('glpi_profiles', ['name' => 'Super-Admin']);
        $this->assert(
            count($profiles) === 1,
            'The isolated fixture database must include its default Super-Admin profile.'
        );
        $relation = new \Profile_User();
        $existing = $relation->find(['users_id' => $id, 'profiles_id' => $profiles[0]['id'], 'entities_id' => 0]);
        if ($existing === []) {
            $this->assert((bool) $relation->add([
                'users_id' => $id,
                'profiles_id' => $profiles[0]['id'],
                'entities_id' => 0,
                'is_recursive' => 1,
            ]), 'Native Profile_User::add failed.');
        }
        $this->assert($user->getFromDB($id), 'Native User::getFromDB failed.');
        return $user;
    }

    /**
     * Initialize the real GLPI session using its native authentication result object.
     *
     * @param \User $user Native account created by createUser().
     * @return void
     * @throws RuntimeException When the native session did not authenticate the requested user.
     */
    public function login(\User $user): void
    {
        $auth = new \Auth();
        $auth->user = $user;
        $auth->auth_succeded = true;
        \Session::init($auth);
        $this->same(
            (int) $user->getID(),
            (int) \Session::getLoginUserID(),
            'Native Session::init did not authenticate the fixture.'
        );
        $administrators = $this->rows('glpi_profiles', ['name' => 'Super-Admin']);
        $this->assert(count($administrators) === 1, 'Missing native administrator profile.');
        \Session::changeProfile((int) $administrators[0]['id']);
    }

    /**
     * Generate fresh, local certificates; keys exist only in the test process.
     *
     * @return array{certificate: string, private_key: string} Ephemeral certificate and matching private key.
     * @throws RuntimeException When OpenSSL cannot generate or export the fixture.
     */
    public function certificate(): array
    {
        if ($this->certificate !== null) {
            return $this->certificate;
        }
        $key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        $this->assert($key !== false, 'OpenSSL could not generate the fixture key.');
        $request = openssl_csr_new(['commonName' => 'samlsso.example.invalid'], $key, ['digest_alg' => 'sha256']);
        $this->assert($request !== false, 'OpenSSL could not generate the fixture request.');
        $certificate = openssl_csr_sign($request, null, $key, 2, ['digest_alg' => 'sha256']);
        $this->assert($certificate !== false, 'OpenSSL could not sign the fixture certificate.');
        $this->assert(openssl_x509_export($certificate, $pem), 'Cannot export the fixture certificate.');
        $this->assert(openssl_pkey_export($key, $private), 'Cannot export the fixture private key.');
        return $this->certificate = ['certificate' => $pem, 'private_key' => $private];
    }

    /**
     * Persist a real provider, replacing the expired public example certificate.
     *
     * @param array $extra Provider fields overriding the valid fixture defaults.
     * @return ConfigEntity The validated and reloaded native provider configuration.
     * @throws RuntimeException When fixture allocation, native persistence, or validation fails.
     */
    public function createProvider(array $extra = []): ConfigEntity
    {
        $certificate = $this->certificate();
        /** Use stable free fixture IDs because legacy login form selectors accept fewer than three digits. */
        $id = 1;
        while ($id < 100 && $this->rows(Config::getTable(), ['id' => $id]) !== []) {
            $id++;
        }
        $this->assert($id < 100, 'No free provider fixture ID below the legacy form selector limit.');
        $fields = $extra + [
            ConfigEntity::ID => $id,
            ConfigEntity::NAME => 'Integration ' . bin2hex(random_bytes(5)),
            ConfigEntity::CONF_DOMAIN => 'example.invalid',
            ConfigEntity::IS_ACTIVE => 1,
            ConfigEntity::SP_CERTIFICATE => $certificate['certificate'],
            ConfigEntity::SP_KEY => $certificate['private_key'],
            ConfigEntity::IDP_CERTIFICATE => $certificate['certificate'],
            ConfigEntity::IDP_ENTITY_ID => 'https://idp.example.invalid/entity',
            ConfigEntity::IDP_SSO_URL => 'https://idp.example.invalid/sso',
            ConfigEntity::IDP_SLO_URL => 'https://idp.example.invalid/slo',
        ] + ConfigDefaultTpl::template();
        $config = new Config();
        $id = $config->add($fields);
        $this->assert(is_int($id) && $id > 0, 'Native Config::add failed.');
        $entity = new ConfigEntity($id);
        $this->assert($entity->isValid(), 'Persisted provider failed validation: '
            . implode('; ', $entity->getErrorMessages()));
        return $entity;
    }

    /**
     * Build parsed claim input with the real OneLogin parser, without claiming signature validation.
     *
     * @param ConfigEntity $provider Persisted provider supplying native toolkit settings.
     * @param array $attributes Attribute names mapped to one or more fixture values.
     * @param string $nameId Fixture subject identifier with the email-address NameID format.
     * @return \OneLogin\Saml2\Response The real parser object; protocol cases separately validate signatures.
     * @throws RuntimeException When the native DOM API does not produce the required element type.
     * @throws \OneLogin\Saml2\Error When the native toolkit rejects provider settings or XML input.
     */
    public function claimResponse(
        ConfigEntity $provider,
        array $attributes,
        string $nameId = 'fixture@example.invalid'
    ): \OneLogin\Saml2\Response {
        $document = new \DOMDocument('1.0', 'UTF-8');
        $response = $document->createElementNS('urn:oasis:names:tc:SAML:2.0:protocol', 'samlp:Response');
        $response->setAttribute('ID', '_' . bin2hex(random_bytes(8)));
        $response->setAttribute('Version', '2.0');
        $response->setAttribute('IssueInstant', gmdate('Y-m-d\TH:i:s\Z'));
        $document->appendChild($response);
        $status = $response->appendChild($document->createElementNS(
            'urn:oasis:names:tc:SAML:2.0:protocol',
            'samlp:Status'
        ));
        $code = $status->appendChild($document->createElementNS(
            'urn:oasis:names:tc:SAML:2.0:protocol',
            'samlp:StatusCode'
        ));
        if (!$code instanceof \DOMElement) {
            throw new RuntimeException('Cannot create the SAML status code element.');
        }
        $code->setAttribute('Value', 'urn:oasis:names:tc:SAML:2.0:status:Success');
        $assertion = $response->appendChild($document->createElementNS(
            'urn:oasis:names:tc:SAML:2.0:assertion',
            'saml:Assertion'
        ));
        if (!$assertion instanceof \DOMElement) {
            throw new RuntimeException('Cannot create the SAML assertion element.');
        }
        $assertion->setAttribute('ID', '_' . bin2hex(random_bytes(8)));
        $assertion->setAttribute('Version', '2.0');
        $assertion->setAttribute('IssueInstant', gmdate('Y-m-d\TH:i:s\Z'));
        $subject = $assertion->appendChild($document->createElementNS(
            'urn:oasis:names:tc:SAML:2.0:assertion',
            'saml:Subject'
        ));
        $identifier = $subject->appendChild($document->createElementNS(
            'urn:oasis:names:tc:SAML:2.0:assertion',
            'saml:NameID'
        ));
        if (!$identifier instanceof \DOMElement) {
            throw new RuntimeException('Cannot create the SAML subject identifier element.');
        }
        $identifier->setAttribute('Format', \OneLogin\Saml2\Constants::NAMEID_EMAIL_ADDRESS);
        $identifier->appendChild($document->createTextNode($nameId));
        $statement = $assertion->appendChild($document->createElementNS(
            'urn:oasis:names:tc:SAML:2.0:assertion',
            'saml:AttributeStatement'
        ));
        foreach ($attributes as $name => $values) {
            $attribute = $statement->appendChild($document->createElementNS(
                'urn:oasis:names:tc:SAML:2.0:assertion',
                'saml:Attribute'
            ));
            if (!$attribute instanceof \DOMElement) {
                throw new RuntimeException('Cannot create the SAML attribute element.');
            }
            $attribute->setAttribute('Name', $name);
            foreach ((array) $values as $value) {
                $item = $attribute->appendChild($document->createElementNS(
                    'urn:oasis:names:tc:SAML:2.0:assertion',
                    'saml:AttributeValue'
                ));
                $item->appendChild($document->createTextNode((string) $value));
            }
        }
        return new \OneLogin\Saml2\Response(
            new \OneLogin\Saml2\Settings($provider->getPhpSamlConfig()),
            base64_encode($document->saveXML())
        );
    }
}
