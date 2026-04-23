<?php

namespace IanSimpson\OAuth2\Admin;

use IanSimpson\OAuth2\Entities\AccessTokenEntity;
use SilverStripe\Forms\FieldList;
use SilverStripe\Forms\GridField\GridField;
use SilverStripe\Forms\GridField\GridFieldConfig_RecordEditor;
use SilverStripe\Core\Extension;
use SilverStripe\Forms\GridField\GridFieldDataColumns;
use SilverStripe\SiteConfig\SiteConfig;

/**
 * @method SiteConfig&static getOwner()
 */
class AccessTokenAdmin extends Extension
{
    protected function updateCMSFields(FieldList $fields): void
    {
        $gridFieldConfig = GridFieldConfig_RecordEditor::create(20);

        $dataColumns = $gridFieldConfig->getComponentByType(GridFieldDataColumns::class);

        if (!$dataColumns instanceof GridFieldDataColumns) {
            return;
        }

        $dataColumns->setDisplayFields([
            'ID' => 'ID',
            'Created' => 'Created',
            'Code' => 'Code',
            'Expiry' => 'Expiry',
            'Revoked' => 'Revoked',
            'ClientID' => 'ClientID',
        ]);
        $grid = GridField::create(
            'AccessTokens',
            'Access Tokens',
            AccessTokenEntity::get()->sort(),
            $gridFieldConfig
        );
        $grid->performReadonlyTransformation();

        $fields->addFieldToTab('Root.OAuth.AccessTokens', $grid);
    }
}
