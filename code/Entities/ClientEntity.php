<?php
/**
 * @author      Ian Simpson <ian@iansimpson.nz>
 * @copyright   Copyright (c) Ian Simpson
 */

namespace IanSimpson\Entities;

use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Entities\Traits\ClientTrait;
use League\OAuth2\Server\Entities\Traits\EntityTrait;

class ClientEntity extends \DataObject implements ClientEntityInterface
{

	protected static $singular_name = 'OAuth Client';
	protected static $plural_name = 'OAuth Clients';

	public static $has_one = array(
		'SiteConfig' => 'SiteConfig'
	);

	public static $db = array(
		'ClientName' => 'Varchar(100)',
		'ClientRedirectUri' => 'Varchar(100)',
		'ClientIdentifier' => 'Varchar(32)',
		'ClientSecret' => 'Varchar(64)',
	);

	public static $summary_fields = array(
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

	public function populateDefaults() {
		parent::populateDefaults();

		$rand = new \RandomGenerator();

		$this->ClientIdentifier = substr($rand->randomToken(),0,32);
		$this->ClientSecret = substr($rand->randomToken(),0,64);
	}
    public function getName() {
    	return $this->ClientName;
    }
    public function getRedirectUri(){
    	return $this->ClientRedirectUri;
    }
    public function getIdentifier() {
    	return $this->ClientIdentifier;
    }
}
