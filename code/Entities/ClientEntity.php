<?php
/**
 * @author      Ian Simpson <ian@iansimpson.nz>
 * @copyright   Copyright (c) Ian Simpson
 */

namespace IanSimpson\Entities;

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
