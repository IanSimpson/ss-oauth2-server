<?php

namespace IanSimpson\Tests;

use DateInterval;
use DateTimeImmutable;
use IanSimpson\OAuth2\Entities\AccessTokenEntity;
use IanSimpson\Tests\Fixtures\AccessTokenEntityExtensionFake;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\Token\Plain;
use League\OAuth2\Server\CryptKey;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\Dev\SapphireTest;
use SilverStripe\Dev\TestOnly;

class AccessTokenEntityTest extends SapphireTest
{
    protected static $required_extensions = [
        AccessTokenEntity::class => [
            AccessTokenEntityExtensionFake::class,
        ]
    ];

    public function testGetPrivateKey(): void
    {
        $cryptKeyFake = $this->createMock(CryptKey::class);
        $entity = AccessTokenEntity::create();

        $this->assertNull($entity->getPrivateKey());

        $entity->setPrivateKey($cryptKeyFake);
        $this->assertEquals($cryptKeyFake, $entity->getPrivateKey());
    }

    public function testGetExpiryDateTime(): void
    {
        $entity = AccessTokenEntity::create();
        $expectedTime = time() + 3600;
        $entity->setExpiryDateTime((new DateTimeImmutable())->add(new DateInterval('PT1H')));

        $this->assertEquals($expectedTime, $entity->getExpiryDateTime()->getTimestamp());
    }
}
