<?php

namespace IanSimpson\Tests;

use SapphireTest;
use IanSimpson\Entities\ClientEntity;

class ClientEntityTest extends SapphireTest
{
    protected $usesDatabase = true;

    public function testValidateFail()
    {
        $this->setExpectedException('ValidationException');

        $e = new ClientEntity();
        $e->write();
    }

    public function testRedirectUriRequired()
    {
        $this->setExpectedException('ValidationException');

        $e = new ClientEntity();
        $e->ClientIdentifier = '200c0e8058c40b101724c23fac8d8ad1';
        $e->ClientSecret = 'b8ca798ab885f49e69507cbe093972bf505a05dd9e34a6fea2d0c3c699d323c4';
        $e->write();
    }

    public function testRedirectUriWhitespace()
    {
        $this->setExpectedException('ValidationException');

        $e = new ClientEntity();
        $e->ClientIdentifier = '200c0e8058c40b101724c23fac8d8ad1';
        $e->ClientSecret = 'b8ca798ab885f49e69507cbe093972bf505a05dd9e34a6fea2d0c3c699d323c4';
        $e->ClientRedirectUri = ' ';
        $e->write();
    }

    public function testValidatePass()
    {
        $e = new ClientEntity();
        $e->ClientIdentifier = '200c0e8058c40b101724c23fac8d8ad1';
        $e->ClientSecret = 'b8ca798ab885f49e69507cbe093972bf505a05dd9e34a6fea2d0c3c699d323c4';
        $e->ClientRedirectUri = 'http://somewhere.lan/oauth2/callback';
        $e->write();
    }
}
