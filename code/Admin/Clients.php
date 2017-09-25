<?php

namespace IanSimpson\Admin;

class ClientAdmin extends \DataExtension {

	private static $has_many = array(
		'Clients' => 'IanSimpson\Entities\ClientEntity',
    );

	public function updateCMSFields(\FieldList $fields) {

		$gridFieldConfig = \GridFieldConfig::create();
		$button = new \GridFieldAddNewButton('toolbar-header-right');
		$button->setButtonName('Add New OAuth Client');
		$gridFieldConfig->addComponents(
			new \GridFieldToolbarHeader(''),
            $button,
			new \GridFieldDataColumns(),
			new \GridFieldEditButton(),
			new \GridFieldDeleteAction(''),
			new \GridFieldDetailForm()
		);

		$fields->addFieldToTab("Root.OAuthConfiguration", new \GridField('Clients', 'Clients', $this->owner->Clients(), $gridFieldConfig));

		return $fields;
	}
}
