<?php
/**
 * @author      Ian Simpson <ian@iansimpson.nz>
 * @copyright   Copyright (c) Ian Simpson
 */

namespace IanSimpson\Entities;

use ValidationResult;
use League\OAuth2\Server\Entities\ClientEntityInterface;

/**
 * @property int SiteConfigID
 * @property string ClientName
 * @property string ClientRedirectUri
 * @property string ClientIdentifier
 * @property string ClientSecret
 * @method \SiteConfig SiteConfig()
 *
 */
class ClientEntity extends \DataObject implements ClientEntityInterface
{
    private static $singular_name = 'OAuth Client';

    private static $plural_name = 'OAuth Clients';

    private static $has_one = array(
        'SiteConfig' => 'SiteConfig'
    );

    private static $db = array(
        'ClientName' => 'Varchar(100)',
        'ClientRedirectUri' => 'Varchar(100)',
        'ClientIdentifier' => 'Varchar(32)',
        'ClientSecret' => 'Varchar(64)',
    );

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

    protected function validate()
    {
        $result = ValidationResult::create();

        if (strlen($this->ClientIdentifier) !== 32) {
            $result->error('Client identifier must be a 32 character random token.');
        }
        if (strlen($this->ClientSecret) !== 64) {
            $result->error('Client secret must be a 64 character random token.');
        }
        if (empty(trim($this->ClientRedirectUri))) {
            $result->error('Client redirect URI must be given.');
        }

        return $result;
    }

    public function populateDefaults()
    {
        parent::populateDefaults();

        $rand = new \RandomGenerator();

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
