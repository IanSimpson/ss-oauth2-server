<?php
/**
 * @author      Ian Simpson <ian@iansimpson.nz>
 * @copyright   Copyright (c) Ian Simpson
 */

namespace IanSimpson\OAuth2\Entities;

use League\OAuth2\Server\Entities\ScopeEntityInterface;
use League\OAuth2\Server\Entities\Traits\EntityTrait;
use SilverStripe\ORM\DataObject;
use SilverStripe\SiteConfig\SiteConfig;

class ScopeEntity extends DataObject implements ScopeEntityInterface
{
    use EntityTrait;

    private static $table_name = 'OAuth_ScopeEntity';

    private static $singular_name = 'OAuth Scope';
    private static $plural_name = 'OAuth Scopes';

    private static $db = [
        'ScopeIdentifier' => 'Varchar(32)',
        'ScopeDescription' => 'Text'
    ];

    private static $has_one = [
        'SiteConfig' => SiteConfig::class
    ];

    private static $summary_fields = [
        'ScopeIdentifier'
    ];

    private static $indexes = [
        'ScopeIdentifier' => [
            'type' => 'index',
            'columns' => ['ScopeIdentifier']
        ],
        'ScopeIdentifierUnique' => [
            'type' => 'unique',
            'columns' => ['ScopeIdentifier']
        ]
    ];

    public function jsonSerialize()
    {
        return $this->ScopeIdentifier;
    }
}
