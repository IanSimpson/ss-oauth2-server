<?php
/**
 * @author      Ian Simpson <ian@iansimpson.nz>
 * @copyright   Copyright (c) Ian Simpson
 */

namespace IanSimpson\OAuth2\Entities;

use League\OAuth2\Server\Entities\ClientEntityInterface;
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
 * @method SiteConfig SiteConfig()
 *
 */
class ClientEntity extends DataObject implements ClientEntityInterface
{
    private static $table_name = 'OAuth_ClientEntity';

    private static $singular_name = 'OAuth Client';
    private static $plural_name = 'OAuth Clients';

    private static $db = [
        'ClientName' => 'Varchar(100)',
        'ClientRedirectUri' => 'Varchar(100)',
        'ClientIdentifier' => 'Varchar(32)',
        'ClientSecret' => 'Varchar(64)'
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

    public function validate()
    {
        $result = ValidationResult::create();

        if (strlen($this->ClientIdentifier) !== 32) {
            $result->addError('Client identifier must be a 32 character random token.');
        }
        if (strlen($this->ClientSecret) !== 64) {
            $result->addError('Client secret must be a 64 character random token.');
        }
        if (empty(trim($this->ClientRedirectUri))) {
            $result->addError('Client redirect URI must be given.');
        }

        return $result;
    }

    public function populateDefaults()
    {
        parent::populateDefaults();

        $rand = new RandomGenerator();

        $this->ClientIdentifier = substr($rand->randomToken(), 0, 32);
        $this->ClientSecret = substr($rand->randomToken(), 0, 64);
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
}
