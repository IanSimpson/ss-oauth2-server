<?php

namespace IanSimpson\OAuth2\Admin;

use IanSimpson\OAuth2\Entities\ClientEntity;
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

class ClientAdmin extends DataExtension
{

    private static $has_many = [
        'Clients' => ClientEntity::class,
    ];

    public function updateCMSFields(FieldList $fields)
    {
        $gridFieldConfig = GridFieldConfig::create();
        $button = new GridFieldAddNewButton('toolbar-header-right');
        $button->setButtonName('Add New OAuth Client');
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
                'Clients',
                'Clients',
                $this->owner->Clients(),
                $gridFieldConfig
            )
        );

        return $fields;
    }
}
