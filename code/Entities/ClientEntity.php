<?php

/**
 * @author      Ian Simpson <ian@iansimpson.nz>
 * @copyright   Copyright (c) Ian Simpson
 */

namespace IanSimpson\OAuth2\Entities;

use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Entities\Traits\ClientTrait;
use SilverStripe\Forms\DropdownField;
use SilverStripe\Forms\FieldList;
use SilverStripe\Forms\ReadonlyField;
use SilverStripe\Forms\TextField;
use SilverStripe\ORM\DataObject;
use SilverStripe\Core\Validation\ValidationResult;
use SilverStripe\Security\RandomGenerator;
use SilverStripe\SiteConfig\SiteConfig;

/**
 * @property ?string $ClientName
 * @property ?string $ClientRedirectUri
 * @property string  $ClientIdentifier
 * @property string  $ClientSecret
 * @property string  $HashedClientSecret
 * @property string  $ClientSecretHashMethod
 * @property string  $ClientSecretHashIterations
 * @property string  $ClientSecretSalt
 * @property string  $ClientGrantType
 * @property bool    $ClientConfidential
 * @property int     $SiteConfigID
 *
 * @method SiteConfig SiteConfig()
 */
class ClientEntity extends DataObject implements ClientEntityInterface
{
    use ClientTrait;

    /**
     * @config
     */
    private static string $hash_method = 'sha512';

    /**
     * @config
     */
    private static int $hash_iterations = 20000;

    /**
     * @config
     */
    private static string $table_name = 'OAuth_ClientEntity';

    /**
     * @config
     */
    private static string $singular_name = 'OAuth Client';

    /**
     * @config
     */
    private static string $plural_name = 'OAuth Clients';

    /**
     * @config
     *
     * @var array|string[]
     */
    private static array $grant_types = [
        'client_credentials' => 'client_credentials',
        'authorization_code' => 'authorization_code',
        'password' => 'password',
        'refresh_token' => 'refresh_token'
    ];

    /**
     * @config
     *
     * @var array<string, string|bool>
     */
    private static array $defaults = [
        'ClientGrantType' => 'client_credentials',
        'ClientConfidential' => true,
    ];

    /**
     * @config
     *
     * @var array|string[]
     */
    private static array $db = [
        'ClientName'                 => 'Varchar(100)',
        'ClientRedirectUri'          => 'Varchar(100)',
        'ClientIdentifier'           => 'Varchar(32)',
        'ClientSecret'               => 'Varchar(64)',
        'HashedClientSecret'         => 'Varchar(128)',
        'ClientSecretHashMethod'     => 'Varchar(50)',
        'ClientSecretHashIterations' => 'Varchar(50)',
        'ClientSecretSalt'           => 'Varchar(50)',
        'ClientConfidential'         => 'Boolean',
        'ClientGrantType'            => 'Text',
    ];

    /**
     * @config
     *
     * @var array|string[]
     */
    private static array $has_one = [
        'SiteConfig' => SiteConfig::class,
    ];

    /**
     * @config
     *
     * @var array|string[]
     */
    private static array $summary_fields = [
        'ClientName',
        'ClientIdentifier',
    ];

    /**
     * @config
     *
     * @var array<string, array{type: string, columns: array<string>}>
     */
    private static array $indexes = [
        'ClientIdentifier' => [
            'type'    => 'index',
            'columns' => ['ClientIdentifier'],
        ],
        'ClientIdentifierUnique' => [
            'type'    => 'unique',
            'columns' => ['ClientIdentifier'],
        ],
    ];

    public function getCMSFields(): FieldList
    {
        $fields = parent::getCMSFields();
        $fields->removeFieldFromTab('Root', 'ClientSecretSalt');
        $fields->removeFieldFromTab('Root', 'ClientSecretHashMethod');
        $fields->removeFieldFromTab('Root', 'ClientSecretHashIterations');
        $fields->removeFieldFromTab('Root', 'ClientSecret');
        $fields->removeFieldFromTab('Root', 'SiteConfigID');

        if (!empty($this->ClientSecret)) {
            $fields->removeFieldFromTab('Root', 'HashedClientSecret');
            $legacySecret = ReadonlyField::create('LegacyClientSecret', 'Legacy client secret')
                ->setValue('<this client secret is insecure - please save client to fix>');
            $fields->insertAfter('ClientIdentifier', $legacySecret);
        } else {
            if (!$this->ID && !empty(trim((string) $this->HashedClientSecret))) {
                // Must use existing field, otherwise loses the initial value. See note in populateDefaults below.
                $secretField = $fields->fieldByName('Root.Main.HashedClientSecret');
                assert($secretField instanceof TextField);
                $secretField->setTitle('Client secret');
                $secretField->setDescription('Please copy this securely to the client. This password will disappear from here forever after save.');
            } else {
                $fields->removeFieldFromTab('Root', 'HashedClientSecret');
                $secretField = ReadonlyField::create('HiddenHashedClientSecret', 'Client secret')
                    ->setValue('<hidden>');
                $fields->insertAfter('ClientIdentifier', $secretField);
            }
        }

        $fields->addFieldToTab(
            'Root.Main',
            DropdownField::create('ClientGrantType', 'Grant Type', (array) self::config()->get('grant_types'))
        );

        return $fields;
    }

    /**
     * {@inheritDoc}
     *
     * @return ValidationResult
     */
    public function validate(): ValidationResult
    {
        $result = ValidationResult::create();

        if (empty(trim((string) $this->ClientIdentifier))) {
            $result->addError('Client identifier must not be empty.');
        }
        if (empty(trim((string) $this->HashedClientSecret)) && empty(trim((string) $this->ClientSecret))) {
            $result->addError('Either client secret hash or client secret must not be empty.');
        }
        if (empty(trim((string) $this->ClientRedirectUri))) {
            $result->addError('Client redirect URI must be given.');
        }

        return $result;
    }

    /**
     * {@inheritDoc}
     */
    public function populateDefaults(): self
    {
        parent::populateDefaults();

        $this->ClientIdentifier = mb_substr((new RandomGenerator())->randomToken(), 0, 32);

        // There is some evil Framework magic that calls populateDefaults twice and yet still somehow
        // manages to save into the DB the initial values. This only works for DB fields that are present
        // in the form, otherwise the secret will change from under the user. If you check Member::onBeforeWrite,
        // that's apparently what you are supposed to do - temporarily store unhashed value in the DB field.
        // ~330 bits of entropy (64 characters [a-z0-9]).
        $this->HashedClientSecret = mb_substr((new RandomGenerator())->randomToken(), 0, 64);

        return $this;
    }

    public function getName(): string
    {
        return (string) $this->ClientName;
    }

    public function getRedirectUri(): string
    {
        return (string) $this->ClientRedirectUri;
    }

    public function getIdentifier(): string
    {
        return (string) $this->ClientIdentifier;
    }

    public function setConfidential(): self
    {
        $this->isConfidential = $this->ClientConfidential;

        return $this;
    }

    public function isSecretValid(string $secret): bool
    {
        // Fallback for historical unhashed tokens.
        if (empty(trim((string) $this->HashedClientSecret))) {
            return $this->ClientSecret === $secret;
        }

        $candidateHash = hash_pbkdf2(
            $this->ClientSecretHashMethod,
            $secret,
            $this->ClientSecretSalt,
            (int) $this->ClientSecretHashIterations
        );

        return $this->HashedClientSecret === $candidateHash;
    }

    protected function onBeforeWrite(): void
    {
        // Overwrite the HashedClientSecret property with the hashed value if needed.
        if (!$this->ID && !empty(trim((string) $this->HashedClientSecret))) {
            $this->storeSafely((string) $this->HashedClientSecret);
        }

        // Automatically fix historical unhashed tokens.
        if (!empty(trim((string) $this->ClientSecret))) {
            $this->storeSafely((string) $this->ClientSecret);
            $this->ClientSecret = '';
        }

        parent::onBeforeWrite();
    }

    private function storeSafely(string $secret): void
    {
        if (empty($this->ClientSecretHashMethod)) {
            $this->ClientSecretHashMethod = self::config()->hash_method;
        }
        if (empty($this->ClientSecretHashIterations)) {
            $this->ClientSecretHashIterations = self::config()->hash_iterations;
        }
        if (empty($this->ClientSecretSalt)) {
            $this->ClientSecretSalt = mb_substr((new RandomGenerator())->randomToken(), 0, 32);
        }

        $this->HashedClientSecret = hash_pbkdf2(
            $this->ClientSecretHashMethod,
            $secret,
            $this->ClientSecretSalt,
            (int) $this->ClientSecretHashIterations
        );
    }
}
