<?php

namespace IanSimpson\Admin;

class ScopeAdmin extends \DataExtension {

	private static $has_many = array(
		'Scopes' => 'IanSimpson\Entities\ScopeEntity',
    );

	public function updateCMSFields(\FieldList $fields) {

		$gridFieldConfig = \GridFieldConfig::create();
		$button = new \GridFieldAddNewButton('toolbar-header-right');
		$button->setButtonName('Add New OAuth Scope');
		$gridFieldConfig->addComponents(
			new \GridFieldToolbarHeader(''),
            $button,
			new \GridFieldDataColumns(),
			new \GridFieldEditButton(),
			new \GridFieldDeleteAction(''),
			new \GridFieldDetailForm()
		);

		$fields->addFieldToTab("Root.OAuthConfiguration", new \GridField('Scopes', 'Scopes', $this->owner->Scopes(), $gridFieldConfig));

		return $fields;
	}
}
