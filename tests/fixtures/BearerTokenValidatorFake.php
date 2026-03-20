<?php

namespace IanSimpson\Tests\Fixtures;

use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Token\Parser;
use Lcobucci\JWT\Token\Plain;
use League\OAuth2\Server\AuthorizationValidators\AuthorizationValidatorInterface;
use Psr\Http\Message\ServerRequestInterface;
use SilverStripe\Dev\TestOnly;

class BearerTokenValidatorFake implements AuthorizationValidatorInterface, TestOnly
{
    /**
     * @inheritDoc
     */
    public function validateAuthorization(ServerRequestInterface $request)
    {
        return null;
    }
}
