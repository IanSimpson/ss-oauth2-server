<?php
/**
 * @author      Ian Simpson <ian@iansimpson.nz>
 * @copyright   Copyright (c) Ian Simpson
 */

namespace IanSimpson\Entities;

use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Entities\ScopeEntityInterface;
use League\OAuth2\Server\Entities\Traits\AccessTokenTrait;
use League\OAuth2\Server\Entities\Traits\EntityTrait;
use League\OAuth2\Server\Entities\Traits\TokenEntityTrait;

class AccessTokenEntity extends \DataObject implements AccessTokenEntityInterface
{
    use AccessTokenTrait, TokenEntityTrait, EntityTrait;

	public static $db = array(
		'Code' => 'Text',
		'Expiry' => 'SS_Datetime',
		'Revoked' => 'Boolean',
	);

	public static $has_one = array(
		'Client' => 'IanSimpson\Entities\ClientEntity',
		'Member' => 'Member',
	);

	public static $many_many = array(
		'ScopeEntities' => 'IanSimpson\Entities\ScopeEntity',
	);

	public function getIdentifier() {
		return $this->Code;
	}

	public function getExpiryDateTime() {
		return new \DateTime( (string) $this->Expiry );
	}

	public function getUserIdentifier() {
		return $this->MemberID;
	}

	public function getScopes() {
		return $this->ScopeEntities()->toArray();
	}

	public function getClient() {
		return ClientEntity::get()->filter(array(
			 'ID' => $this->ClientID
		))->first();
	}


	public function setIdentifier($code) {
		$this->Code = $code;
	}

	public function setExpiryDateTime(\DateTime $expiry) {
		$this->Expiry = new \SS_Datetime;
		$this->Expiry->setValue( $expiry->getTimestamp() );
	}

	public function setUserIdentifier($id) {
		$this->MemberID = $id;
	}

    public function addScope(ScopeEntityInterface $scope) {
    	$this->ScopeEntities->push($scope);
    }

	public function setScopes($scopes) {
		$this->ScopeEntities = new \ArrayList($scopes);;
	}

	public function setClient(ClientEntityInterface $client) {
		$this->ClientID = $client->ID;
	}
}
