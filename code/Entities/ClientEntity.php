<?php
/**
 * @author      Ian Simpson <ian@iansimpson.nz>
 * @copyright   Copyright (c) Ian Simpson
 */

namespace IanSimpson\OAuth2\Entities;

use League\OAuth2\Server\Entities\ClientEntityInterface;
use SilverStripe\Forms\ReadonlyField;
use SilverStripe\ORM\DataObject;
use SilverStripe\ORM\ValidationResult;
use SilverStripe\Security\RandomGenerator;
use SilverStripe\SiteConfig\SiteConfig;

/**
 * @property int SiteConfigID
 * @property string ClientName
 * @property string ClientRedirectUri
 * @property string ClientIdentifier
 * @property string ClientSecret
 * @property string HashedClientSecret
 * @property string ClientSecretHashMethod
 * @property string ClientSecretHashIterations
 * @property string ClientSecretSalt
 * @method SiteConfig SiteConfig()
 *
 */
class ClientEntity extends DataObject implements ClientEntityInterface
{
    private static $hash_method = 'sha512';

    private static $hash_iterations = 20000;

    private static $table_name = 'OAuth_ClientEntity';

    private static $singular_name = 'OAuth Client';

    private static $plural_name = 'OAuth Clients';

    private static $db = [
        'ClientName' => 'Varchar(100)',
        'ClientRedirectUri' => 'Varchar(100)',
        'ClientIdentifier' => 'Varchar(32)',
        'ClientSecret' => 'Varchar(64)',
        'HashedClientSecret' => 'Varchar(128)',
        'ClientSecretHashMethod' => 'Varchar(50)',
        'ClientSecretHashIterations' => 'Varchar(50)',
        'ClientSecretSalt' => 'Varchar(50)',
    ];

    private static $has_one = [
        'SiteConfig' => SiteConfig::class
    ];

    private static $summary_fields = [
        'ClientName',
        'ClientIdentifier'
    ];

    private static $indexes = [
        'ClientIdentifier' => [
            'type' => 'index',
            'columns' => ['ClientIdentifier']
        ],
        'ClientIdentifierUnique' => [
            'type' => 'unique',
            'columns' => ['ClientIdentifier']
        ]
    ];

    /**
     * @var string For passing between populateDefaults and getCMSFields.
     */
    private $rawSecret = '<hidden>';

    public function getCMSFields()
    {
        $fields = parent::getCMSFields();
        $fields->removeFieldFromTab('Root', 'HashedClientSecret');
        $fields->removeFieldFromTab('Root', 'ClientSecretSalt');
        $fields->removeFieldFromTab('Root', 'ClientSecretHashMethod');
        $fields->removeFieldFromTab('Root', 'ClientSecretHashIterations');
        $fields->removeFieldFromTab('Root', 'ClientSecret');
        $fields->removeFieldFromTab('Root', 'SiteConfigID');

        if (!empty($this->ClientSecret)) {
            $legacySecret = ReadonlyField::create('LegacyClientSecret', 'Legacy client secret')
                ->setValue('<this client secret is insecure - please save client to fix>');
            $fields->insertAfter('ClientIdentifier', $legacySecret);
        } else {
            $secretField = ReadonlyField::create('InMemoryClientSecret', 'Client secret')
                ->setValue($this->rawSecret);
            if ($this->rawSecret !== '<hidden>') {
                $secretField->setRightTitle('Please copy this securely to the client. This password will disappear from here forever after reload.');
            }
            $fields->insertAfter('ClientIdentifier', $secretField);
        }

        return $fields;
    }

    public function validate()
    {
        $result = ValidationResult::create();

        if (empty(trim($this->ClientIdentifier))) {
            $result->addError('Client identifier must not be empty.');
        }
        if (empty(trim($this->HashedClientSecret)) && empty(trim($this->ClientSecret))) {
            $result->addError('Either client secret hash or client secret must not be empty.');
        }
        if (empty(trim($this->ClientRedirectUri))) {
            $result->addError('Client redirect URI must be given.');
        }

        return $result;
    }

    public function populateDefaults()
    {
        parent::populateDefaults();
        $this->ClientIdentifier = substr((new RandomGenerator())->randomToken(), 0, 32);
        // ~330 bits of entropy (64 characters [a-z0-9]).
        $this->rawSecret = substr((new RandomGenerator())->randomToken(), 0, 64);
        $this->storeSafely($this->rawSecret);
    }

    public function onBeforeWrite()
    {
        // Automatically fix historical unhashed tokens.
        if (!empty(trim($this->ClientSecret))) {
            $this->storeSafely($this->ClientSecret);
            $this->ClientSecret = '';
        }
        
        parent::onBeforeWrite();
    }

    public function getName()
    {
        return $this->ClientName;
    }

    public function getRedirectUri()
    {
        return $this->ClientRedirectUri;
    }

    public function getIdentifier()
    {
        return $this->ClientIdentifier;
    }

    public function isSecretValid($secret)
    {
        // Fallback for historical unhashed tokens.
        if (empty(trim($this->HashedClientSecret))) {
            return $this->ClientSecret === $secret;
        }

        $candidateHash = hash_pbkdf2(
            $this->ClientSecretHashMethod,
            $secret,
            $this->ClientSecretSalt,
            $this->ClientSecretHashIterations
        );

        return $this->HashedClientSecret === $candidateHash;
    }

    private function storeSafely($secret)
    {
        if (empty($this->ClientSecretHashMethod)) {
            $this->ClientSecretHashMethod = $this->config()->hash_method;
        }
        if (empty($this->ClientSecretHashIterations)) {
            $this->ClientSecretHashIterations = $this->config()->hash_iterations;
        }
        if (empty($this->ClientSecretSalt)) {
            $this->ClientSecretSalt = substr((new RandomGenerator())->randomToken(), 0, 32);
        }

        $this->HashedClientSecret = hash_pbkdf2(
            $this->ClientSecretHashMethod,
            $secret,
            $this->ClientSecretSalt,
            $this->ClientSecretHashIterations
        );
    }
}
