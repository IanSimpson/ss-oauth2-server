<?php
/**
 * @author      Ian Simpson <ian@iansimpson.nz>
 * @copyright   Copyright (c) Ian Simpson
 */

namespace IanSimpson\Entities;

use League\OAuth2\Server\Entities\RefreshTokenEntityInterface;
use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\Traits\EntityTrait;
use League\OAuth2\Server\Entities\Traits\RefreshTokenTrait;

/**
 * @property string Code
 * @property string Expiry
 * @property bool Revoked
 * @property int AccessTokenID
 * @method AccessTokenEntity AccessToken()
 */
class RefreshTokenEntity extends \DataObject implements RefreshTokenEntityInterface
{
    use RefreshTokenTrait, EntityTrait;

    private static $db = array(
        'Code' => 'Text',
        'Expiry' => 'SS_Datetime',
        'Revoked' => 'Boolean',
    );

    private static $has_one = array(
        'AccessToken' => 'IanSimpson\Entities\AccessTokenEntity',
    );

    public function getIdentifier()
    {
        return $this->Code;
    }

    public function getExpiryDateTime()
    {
        return new \DateTime((string) $this->Expiry);
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
        $this->Expiry = new \SS_Datetime;
        $this->Expiry->setValue($expiry->getTimestamp());
    }

    public function setAccessToken(AccessTokenEntityInterface $accessToken)
    {
        /** @var AccessTokenEntity $accessTokenEntity */
        $accessTokenEntity = $accessToken;
        $this->AccessTokenID = $accessTokenEntity->ID;
    }
}
