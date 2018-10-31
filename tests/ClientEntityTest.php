<?php

namespace IanSimpson\Tests;

use SilverStripe\Dev\SapphireTest;
use IanSimpson\OAuth2\Entities\ClientEntity;
use SilverStripe\ORM\ValidationException;

class ClientEntityTest extends SapphireTest
{
    protected $usesDatabase = true;

    public function testRedirectUriRequired()
    {
        $this->expectException(ValidationException::class);

        $e = new ClientEntity();
        $e->populateDefaults();
        $e->write();
    }

    public function testRedirectUriWhitespace()
    {
        $this->expectException(ValidationException::class);

        $e = new ClientEntity();
        $e->populateDefaults();
        $e->ClientRedirectUri = ' ';
        $e->write();
    }

    public function testValidatePass()
    {
        $e = new ClientEntity();
        $e->populateDefaults();
        $e->ClientRedirectUri = 'http://somewhere.lan/oauth2/callback';
        $e->write();
    }

    public function testLegacySecretMigratesToHashed()
    {
        $e = new ClientEntity();
        $e->ClientIdentifier = '123';
        $e->ClientSecret = 'abc';
        $e->ClientRedirectUri = 'http://somewhere.lan/oauth2/callback';
        $e->write();

        $this->assertTrue(empty($e->ClientSecret));
        $this->assertTrue($e->isSecretValid('abc'));
    }

    public function testSecretWorks()
    {
        $e = new ClientEntity();
        $e->populateDefaults();

        $secret = $e->getCMSFields()->fieldByName('Root.Main.InMemoryClientSecret')->Value();
        $this->assertTrue(empty($e->ClientSecret));
        $this->assertTrue($e->isSecretValid($secret));
    }

    public function testSecretIsNotAvailableAfterWriting()
    {
        $e = new ClientEntity();
        $e->ClientRedirectUri = 'http://somewhere.lan/oauth2/callback';
        $e->populateDefaults();
        $e->write();

        $refreshed = ClientEntity::get()->byID($e->ID);
        $secret = $refreshed->getCMSFields()->fieldByName('Root.Main.InMemoryClientSecret')->Value();
        $this->assertEquals($secret, '<hidden>');
    }

    public function testLegacyWarningIsShown()
    {
        $e = new ClientEntity();
        $e->ClientIdentifier = '123';
        $e->ClientSecret = 'abc';
        $e->ClientRedirectUri = 'http://somewhere.lan/oauth2/callback';

        $legacyField = $e->getCMSFields()->fieldByName('Root.Main.LegacyClientSecret');
        $this->assertNotNull($legacyField);
    }
}
