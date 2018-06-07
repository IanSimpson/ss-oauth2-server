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
use SilverStripe\ORM\FieldType\DBDateTime;

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
        return new DateTime((string) $this->Expiry);
    }

    public function getAccessToken()
    {
        return AccessTokenEntity::get()->filter([
             'ID' => $this->AccessTokenID
        ])->first();
    }

    public function setIdentifier($code)
    {
        $this->Code = $code;
    }

    public function setExpiryDateTime(\DateTime $expiry)
    {
        $this->Expiry = new DBDatetime;
        $this->Expiry->setValue($expiry->getTimestamp());
    }

    public function setAccessToken(AccessTokenEntityInterface $accessToken)
    {
        $this->AccessTokenID = $accessToken->ID;
    }
}
