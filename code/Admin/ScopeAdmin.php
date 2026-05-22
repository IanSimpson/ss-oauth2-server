<?php

namespace IanSimpson\OAuth2\Admin;

use IanSimpson\OAuth2\Entities\ScopeEntity;
use SilverStripe\Forms\FieldList;
use SilverStripe\Forms\GridField\GridField;
use SilverStripe\Forms\GridField\GridFieldAddNewButton;
use SilverStripe\Forms\GridField\GridFieldConfig;
use SilverStripe\Forms\GridField\GridFieldDataColumns;
use SilverStripe\Forms\GridField\GridFieldDeleteAction;
use SilverStripe\Forms\GridField\GridFieldDetailForm;
use SilverStripe\Forms\GridField\GridFieldEditButton;
use SilverStripe\Core\Extension;
use SilverStripe\Forms\GridField\GridFieldToolbarHeader;
use SilverStripe\ORM\HasManyList;

/**
 * @method HasManyList<ScopeEntity> Scopes()
 */
class ScopeAdmin extends Extension
{
    /**
     * @var array|string[]
     *
     * @config
     */
    private static array $has_many = [
        'Scopes' => ScopeEntity::class,
    ];

    protected function updateCMSFields(FieldList $fields): void
    {
        $gridFieldConfig = GridFieldConfig::create();
        $button = GridFieldAddNewButton::create('toolbar-header-right');
        $button->setButtonName('Add New OAuth Scope');
        $gridFieldConfig->addComponents(
            GridFieldToolbarHeader::create(),
            $button,
            GridFieldDataColumns::create(),
            GridFieldEditButton::create(),
            GridFieldDeleteAction::create(),
            GridFieldDetailForm::create()
        );

        $fields->addFieldToTab('Root.OAuth.Configuration', GridField::create(
            'Scopes',
            'Scopes',
            $this->getOwner()->Scopes(),
            $gridFieldConfig
        ));
    }
}
