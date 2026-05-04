<?php

namespace IanSimpson\Tests\Fixtures;

use League\OAuth2\Server\AuthorizationValidators\AuthorizationValidatorInterface;
use Psr\Http\Message\ServerRequestInterface;
use SilverStripe\Dev\TestOnly;

class BearerTokenValidatorFake implements AuthorizationValidatorInterface, TestOnly
{
    /**
     * @inheritDoc
     */
    public function validateAuthorization(ServerRequestInterface $request): ServerRequestInterface
    {
        return $request;
    }
}
