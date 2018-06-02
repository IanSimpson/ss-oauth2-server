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
use SilverStripe\Forms\GridField\GridFieldToolbarHeader;
use SilverStripe\ORM\DataExtension;

class ScopeAdmin extends DataExtension
{

    private static $has_many = [
        'Scopes' => ScopeEntity::class,
    ];

    public function updateCMSFields(FieldList $fields)
    {
        $gridFieldConfig = GridFieldConfig::create();
        $button = new GridFieldAddNewButton('toolbar-header-right');
        $button->setButtonName('Add New OAuth Scope');
        $gridFieldConfig->addComponents(
            new GridFieldToolbarHeader(''),
            $button,
            new GridFieldDataColumns(),
            new GridFieldEditButton(),
            new GridFieldDeleteAction(''),
            new GridFieldDetailForm()
        );

        $fields->addFieldToTab(
            "Root.OAuthConfiguration",
            new GridField(
                'Scopes',
                'Scopes',
                $this->owner->Scopes(),
                $gridFieldConfig
            )
        );

        return $fields;
    }
}
