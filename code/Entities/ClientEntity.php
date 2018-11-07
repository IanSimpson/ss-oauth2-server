<?php
/**
 * @author      Ian Simpson <ian@iansimpson.nz>
 * @copyright   Copyright (c) Ian Simpson
 */

namespace IanSimpson\Entities;

use RandomGenerator;
use ReadonlyField;
use ValidationResult;
use League\OAuth2\Server\Entities\ClientEntityInterface;

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
 * @method \SiteConfig SiteConfig()
 *
 */
class ClientEntity extends \DataObject implements ClientEntityInterface
{
    private static $hash_method = 'sha512';

    private static $hash_iterations = 20000;

    private static $singular_name = 'OAuth Client';

    private static $plural_name = 'OAuth Clients';

    private static $has_one = array(
        'SiteConfig' => 'SiteConfig'
    );

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

    private static $summary_fields = array(
        'ClientName',
        'ClientIdentifier'
    );

    private static $indexes = array(
        'ClientIdentifier' => array(
            'type' => 'index',
            'value' => '"ClientIdentifier"',
        ),
        'ClientIdentifierUnique' => array(
            'type' => 'unique',
            'value' => '"ClientIdentifier"',
        ),
    );

    public function getCMSFields()
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
            if (!$this->ID && !empty(trim($this->HashedClientSecret))) {
                // Must use existing field, otherwise loses the initial value. See note in populateDefaults below.
                /** @var \FormField $secretField */
                $secretField = $fields->fieldByName('Root.Main.HashedClientSecret');
                $secretField->setTitle('Client secret');
                $secretField->setRightTitle('Please copy this securely to the client. This password will disappear from here forever after save.');
            } else {
                $fields->removeFieldFromTab('Root', 'HashedClientSecret');
                $secretField = ReadonlyField::create('HiddenHashedClientSecret', 'Client secret')
                    ->setValue('<hidden>');
                $fields->insertAfter('ClientIdentifier', $secretField);
            }
        }

        return $fields;
    }

    protected function validate()
    {
        $result = ValidationResult::create();

        if (empty(trim($this->ClientIdentifier))) {
            $result->error('Client identifier must not be empty.');
        }
        if (empty(trim($this->HashedClientSecret)) && empty(trim($this->ClientSecret))) {
            $result->error('Either client secret hash or client secret must not be empty.');
        }
        if (empty(trim($this->ClientRedirectUri))) {
            $result->error('Client redirect URI must be given.');
        }

        return $result;
    }

    public function populateDefaults()
    {
        parent::populateDefaults();

        $this->ClientIdentifier = substr((new RandomGenerator())->randomToken(), 0, 32);

        // There is some evil Framework magic that calls populateDefaults twice and yet still somehow
        // manages to save into the DB the initial values. This only works for DB fields that are present
        // in the form, otherwise the secret will change from under the user. If you check Member::onBeforeWrite,
        // that's apparently what you are supposed to do - temporarily store unhashed value in the DB field.
        // ~330 bits of entropy (64 characters [a-z0-9]).
        $this->HashedClientSecret = substr((new RandomGenerator())->randomToken(), 0, 64);
    }

    public function onBeforeWrite()
    {
        // Overwrite the HashedClientSecret property with the hashed value if needed.
        if (!$this->ID && !empty(trim($this->HashedClientSecret))) {
            $this->storeSafely($this->HashedClientSecret);
        }

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
