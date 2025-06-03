<?php

namespace IanSimpson\Tests\Fixtures;

use Lcobucci\JWT\Token;
use Lcobucci\JWT\Token\DataSet;
use Lcobucci\JWT\Token\Plain;
use Lcobucci\JWT\Token\Signature;
use SilverStripe\Core\Extension;
use SilverStripe\Dev\TestOnly;

class AccessTokenEntityExtensionFake extends Extension implements TestOnly
{
    public function updateJWT(&$token)
    {
        $headers   = new DataSet(['alg' => 'none'], 'headers');
        $claims    = new DataSet([], 'claims');
        $signature = new Signature('hash', 'signature');
        $token = new Plain($headers, $claims, $signature);
    }
}
