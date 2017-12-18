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

class RefreshTokenEntity extends \DataObject implements RefreshTokenEntityInterface
{
    use RefreshTokenTrait, EntityTrait;

	public static $db = array(
		'Code' => 'Text',
		'Expiry' => 'SS_Datetime',
		'Revoked' => 'Boolean',
	);

	public static $has_one = array(
		'AccessToken' => 'IanSimpson\Entities\AccessTokenEntity',
	);

	public function getIdentifer() {
		return $this->Code;
	}

	public function getExpiryDateTime() {
		return new \DateTime( (string) $this->Expiry );
	}

	public function getAccessToken() {
		return AccessTokenEntity::get()->filter(array(
			 'ID' => $this->AccessTokenID
		))->first();
	}


	public function setIdentifer($code) {
		$this->Code = $code;
	}

	public function setExpiryDateTime(\DateTime $expiry) {
		$this->Expiry = new \SS_Datetime;
		$this->Expiry->setValue( $expiry->getTimestamp() );
	}

	public function setAccessToken(AccessTokenEntityInterface $accessToken) {
		$this->AccessTokenID = $accessToken->ID;
	}
}
