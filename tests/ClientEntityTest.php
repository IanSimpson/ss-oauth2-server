<?php

namespace IanSimpson\Tests;

use IanSimpson\OAuth2\Entities\ClientEntity;
use SilverStripe\Dev\SapphireTest;
use SilverStripe\Forms\DropdownField;
use SilverStripe\Core\Validation\ValidationException;

/**
 * @internal
 */
class ClientEntityTest extends SapphireTest
{
    /**
     * @var mixed
     */
    protected $usesDatabase = true;

    public function testRedirectUriRequired(): void
    {
        $this->expectException(ValidationException::class);

        $e = ClientEntity::create();
        $e->populateDefaults();
        $e->write();
    }

    public function testRedirectUriWhitespace(): void
    {
        $this->expectException(ValidationException::class);

        $e = ClientEntity::create();
        $e->populateDefaults();
        $e->ClientRedirectUri = ' ';
        $e->write();
    }

    public function testValidatePass(): void
    {
        $this->expectNotToPerformAssertions();

        $e = ClientEntity::create();
        $e->populateDefaults();
        $e->ClientRedirectUri = 'http://somewhere.lan/oauth2/callback';
        $e->write();
    }

    public function testLegacySecretMigratesToHashed(): void
    {
        $e                    = ClientEntity::create();
        $e->ClientIdentifier  = '123';
        $e->ClientSecret      = 'abc';
        $e->ClientRedirectUri = 'http://somewhere.lan/oauth2/callback';
        $e->write();

        $this->assertTrue(empty($e->ClientSecret));
        $this->assertTrue($e->isSecretValid('abc'));
    }

    public function testSecretWorks(): void
    {
        $e                    = ClientEntity::create();
        $e->ClientRedirectUri = 'http://somewhere.lan/oauth2/callback';
        $e->populateDefaults();

        $secret = $e->HashedClientSecret;

        $e->write();

        $this->assertNotSame($secret, $e->HashedClientSecret);
        $this->assertTrue(empty($e->ClientSecret));
        $this->assertTrue($e->isSecretValid($secret));
    }

    public function testSecretIsNotAvailableAfterWriting(): void
    {
        $e                    = ClientEntity::create();
        $e->ClientRedirectUri = 'http://somewhere.lan/oauth2/callback';
        $e->populateDefaults();
        $e->write();

        $refreshed   = ClientEntity::get()->byID($e->ID);
        $secretField = $refreshed->getCMSFields()->fieldByName('Root.Main.HashedClientSecret');
        $this->assertNull($secretField);
        $hiddenSecret = $refreshed->getCMSFields()->fieldByName('Root.Main.HiddenHashedClientSecret')?->getValue();
        $this->assertSame($hiddenSecret, '<hidden>');
    }

    public function testLegacyWarningIsShown(): void
    {
        $e                    = ClientEntity::create();
        $e->ClientIdentifier  = '123';
        $e->ClientSecret      = 'abc';
        $e->ClientRedirectUri = 'http://somewhere.lan/oauth2/callback';

        $secret = $e->getCMSFields()->fieldByName('Root.Main.HashedClientSecret');
        $this->assertNull($secret);
        $legacyField = $e->getCMSFields()->fieldByName('Root.Main.LegacyClientSecret');
        $this->assertNotNull($legacyField);
    }

    public function testCMSFields(): void
    {
        $fields = ClientEntity::create()->getCMSFields();

        $visibleFields = [
            'ClientGrantType' => DropdownField::class,
        ];

        foreach ($visibleFields as $fieldName => $classType) {
            $this->assertInstanceOf($classType, $fields->dataFieldByName($fieldName));
        }
    }
}
