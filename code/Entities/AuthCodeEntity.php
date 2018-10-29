<?php
/**
 * @author      Ian Simpson <ian@iansimpson.nz>
 * @copyright   Copyright (c) Ian Simpson
 */

namespace IanSimpson\Entities;

use League\OAuth2\Server\Entities\AuthCodeEntityInterface;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Entities\ScopeEntityInterface;
use League\OAuth2\Server\Entities\Traits\AuthCodeTrait;
use League\OAuth2\Server\Entities\Traits\EntityTrait;
use League\OAuth2\Server\Entities\Traits\TokenEntityTrait;

/**
 * @property string Code
 * @property string Expiry
 * @property bool Revoked
 * @property int ClientID
 * @property int MemberID
 * @property \SS_List ScopeEntities
 * @method ClientEntity Client()
 * @method \Member Member()
 * @method \ManyManyList ScopeEntities()
 */
class AuthCodeEntity extends \DataObject implements AuthCodeEntityInterface
{
    use EntityTrait, TokenEntityTrait, AuthCodeTrait;

    private static $db = array(
        'Code' => 'Text',
        'Expiry' => 'SS_Datetime',
        'Revoked' => 'Boolean',
    );

    private static $has_one = array(
        'Client' => 'IanSimpson\Entities\ClientEntity',
        'Member' => 'Member',
    );

    private static $many_many = array(
        'ScopeEntities' => 'IanSimpson\Entities\ScopeEntity',
    );

    public function getIdentifier()
    {
        return $this->Code;
    }

    public function getExpiryDateTime()
    {
        return new \DateTime((string) $this->Expiry);
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
        $clients = ClientEntity::get()->filter(array(
             'ID' => $this->ClientID
        ));
        /** @var ClientEntity $client */
        $client = $clients->first();
        return $client;
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

    public function setUserIdentifier($id)
    {
        $this->MemberID = $id;
    }

    public function addScope(ScopeEntityInterface $scope)
    {
        $this->ScopeEntities()->push($scope);
    }

    public function setScopes($scopes)
    {
        $this->ScopeEntities = new \ArrayList($scopes);
        ;
    }

    public function setClient(ClientEntityInterface $client)
    {
        /** @var ClientEntity $clientEntity */
        $clientEntity = $client;
        $this->ClientID = $clientEntity->ID;
    }
}
