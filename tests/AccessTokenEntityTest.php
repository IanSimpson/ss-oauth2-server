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

    public function testGetExpiryDateTime(): void
    {
        $entity = AccessTokenEntity::create();
        $expectedTime = time() + 3600;
        $entity->setExpiryDateTime((new DateTimeImmutable())->add(new DateInterval('PT1H')));

        $this->assertEquals($expectedTime, $entity->getExpiryDateTime()->getTimestamp());
    }
}
