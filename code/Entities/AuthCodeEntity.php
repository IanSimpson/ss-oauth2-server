<?php
/**
 * @author      Ian Simpson <ian@iansimpson.nz>
 * @copyright   Copyright (c) Ian Simpson
 */

namespace IanSimpson\OAuth2\Entities;

use DateTime;
use League\OAuth2\Server\Entities\AuthCodeEntityInterface;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Entities\ScopeEntityInterface;
use League\OAuth2\Server\Entities\Traits\AuthCodeTrait;
use League\OAuth2\Server\Entities\Traits\EntityTrait;
use League\OAuth2\Server\Entities\Traits\TokenEntityTrait;
use SilverStripe\ORM\ArrayList;
use SilverStripe\ORM\DataObject;
use SilverStripe\Security\Member;

class AuthCodeEntity extends DataObject implements AuthCodeEntityInterface
{
    use EntityTrait, TokenEntityTrait, AuthCodeTrait;

    private static $table_name = 'OAuth_AuthCodeEntity';

    private static $db = [
        'Code' => 'Text',
        'Expiry' => 'Datetime',
        'Revoked' => 'Boolean'
    ];

    private static $has_one = [
        'Client' => ClientEntity::class,
        'Member' => Member::class
    ];

    private static $many_many = [
        'ScopeEntities' => ScopeEntity::class
    ];

    public function getIdentifier()
    {
        return $this->Code;
    }

    public function getExpiryDateTime()
    {
        return new DateTime(date('Y-m-d H:i:s', $this->Expiry));
    }

    public function getUserIdentifier()
    {
        return $this->MemberID;
    }

    public function getScopes()
    {
        return $this->ScopeEntities()->toArray();
    }

    public function getClient()
    {
        return ClientEntity::get()->filter([
             'ID' => $this->ClientID
        ])->first();
    }


    public function setIdentifier($code)
    {
        $this->Code = $code;
    }

    public function setExpiryDateTime(DateTime $expiry)
    {
        $this->Expiry = $expiry->getTimestamp();
    }

    public function setUserIdentifier($id)
    {
        $this->MemberID = $id;
    }

    public function addScope(ScopeEntityInterface $scope)
    {
        $this->ScopeEntities()->add($scope);
    }

    public function setScopes($scopes)
    {
        $this->ScopeEntities()->removeAll();
        foreach($scopes as $scope) {
            $this->addScope($scope);
        }
    }

    public function setClient(ClientEntityInterface $client)
    {
        $this->ClientID = $client->ID;
    }
}
