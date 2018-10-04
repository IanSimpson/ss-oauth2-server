<?php
/**
 * @author      Ian Simpson <ian@iansimpson.nz>
 * @copyright   Copyright (c) Ian Simpson
 */

namespace IanSimpson\Entities;

use League\OAuth2\Server\Entities\ScopeEntityInterface;
use League\OAuth2\Server\Entities\Traits\EntityTrait;

/**
 * @property int SiteConfigID
 * @property string ScopeIdentifier
 * @property string ScopeDescription
 * @method \SiteConfig SiteConfig()
 */
class ScopeEntity extends \DataObject implements ScopeEntityInterface
{
    use EntityTrait;

    protected static $singular_name = 'OAuth Scope';
    protected static $plural_name = 'OAuth Scopes';

    public static $has_one = array(
        'SiteConfig' => 'SiteConfig'
    );

    public static $db = array(
        'ScopeIdentifier' => 'Varchar(32)',
        'ScopeDescription' => 'Text',
    );

    public static $summary_fields = array(
        'ScopeIdentifier',
    );

    private static $indexes = array(
        'ScopeIdentifier' => array(
            'type' => 'index',
            'value' => '"ScopeIdentifier"',
        ),
        'ScopeIdentifierUnique' => array(
            'type' => 'unique',
            'value' => '"ScopeIdentifier"',
        ),
    );

    public function jsonSerialize()
    {
        return $this->ScopeIdentifier;
    }
}
