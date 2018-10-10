<?php
/**
 * @author      Ian Simpson <ian@iansimpson.nz>
 * @copyright   Copyright (c) Ian Simpson
 */

namespace IanSimpson\OAuth2\Entities;

use DateTime;
use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\RefreshTokenEntityInterface;
use League\OAuth2\Server\Entities\Traits\EntityTrait;
use League\OAuth2\Server\Entities\Traits\RefreshTokenTrait;
use SilverStripe\ORM\DataObject;

/**
 * @property string Code
 * @property string Expiry
 * @property bool Revoked
 * @property int AccessTokenID
 * @method AccessTokenEntity AccessToken()
 */
class RefreshTokenEntity extends DataObject implements RefreshTokenEntityInterface
{
    use RefreshTokenTrait, EntityTrait;

    private static $table_name = 'OAuth_RefreshTokenEntity';

    private static $db = [
        'Code' => 'Text',
        'Expiry' => 'Datetime',
        'Revoked' => 'Boolean'
    ];

    private static $has_one = [
        'AccessToken' => AccessTokenEntity::class
    ];

    public function getIdentifier()
    {
        return $this->Code;
    }

    public function getExpiryDateTime()
    {
        $date = new DateTime();
        $date->setTimestamp((int) $this->Expiry);

        return $date;
    }

    public function getAccessToken()
    {
        $accessTokens = AccessTokenEntity::get()->filter(array(
            'ID' => $this->AccessTokenID
        ));
        /** @var AccessTokenEntity $accessToken */
        $accessToken = $accessTokens->first();
        return $accessToken;
    }

    public function setIdentifier($code)
    {
        $this->Code = $code;
    }

    public function setExpiryDateTime(\DateTime $expiry)
    {
        $this->Expiry = $expiry->getTimestamp();
    }

    public function setAccessToken(AccessTokenEntityInterface $accessToken)
    {
        /** @var AccessTokenEntity $accessTokenEntity */
        $accessTokenEntity = $accessToken;
        $this->AccessTokenID = $accessTokenEntity->ID;
    }
}
