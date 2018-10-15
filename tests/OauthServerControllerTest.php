<?php

namespace IanSimpson\Tests;

use Config;
use Injector;
use FunctionalTest;
use function GuzzleHttp\Psr7\parse_query;
use IanSimpson\Entities\AccessTokenEntity;
use IanSimpson\Entities\AuthCodeEntity;
use IanSimpson\Entities\ClientEntity;
use IanSimpson\OauthServerController;
use IanSimpson\Repositories\AccessTokenRepository;
use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use League\OAuth2\Server\AuthorizationValidators\BearerTokenValidator;
use League\OAuth2\Server\CryptKey;
use League\OAuth2\Server\CryptTrait;
use Monolog\Logger;

class OauthServerControllerTest extends FunctionalTest
{
    use CryptTrait;

    protected static $fixture_file = 'OauthServerControllerTest.yml';

    protected $autoFollowRedirection = false;

    private $logger;

    public function setUp()
    {
        parent::setUp();

        Config::nest();

        $_SERVER['SERVER_PORT'] = 80;

        $encryptionKey = 'abc';
        $this->setEncryptionKey($encryptionKey);
        Config::inst()->update(OauthServerController::class, 'encryptionKey', $encryptionKey);
        Config::inst()->update(OauthServerController::class, 'privateKey', 'ss-oauth2-server/tests/test.key');
        Config::inst()->update(OauthServerController::class, 'publicKey', 'ss-oauth2-server/tests/test.crt');

        chmod(__DIR__ . '/test.key', 0600);
        chmod(__DIR__ . '/test.crt', 0600);

        $this->logger = $this->getMockBuilder(Logger::class)
            ->disableOriginalConstructor()
            ->getMock();

        Injector::inst()->registerService($this->logger, 'OAuthLogger');
    }

    public function tearDown()
    {
        parent::tearDown();

        Config::unnest();
    }

    public function testAuthorize()
    {
        $state = 789;
        $c = $this->objFromFixture(ClientEntity::class, 'test');
        $m = $this->objFromFixture('Member', 'joe');
        $this->session()->inst_set('loggedInAs', $m->ID);

        $this->logger->expects($this->once())
            ->method('info')
            ->with($this->equalTo(
                'joe@joe.org authorised test (123) to access scopes "read_profile" on their behalf'
            ));

        $resp = $this->get(sprintf(
            'oauth/authorize?client_id=%s&redirect_uri=%s&response_type=code&scope=read_profile&state=%s',
            $c->ClientIdentifier,
            urlencode('http://client/callback'),
            $state
        ));

        $this->assertEquals(302, $resp->getStatusCode());
        $url = parse_url($resp->getHeader('Location'));
        $query = parse_query($url['query']);
        $this->assertEquals($url['host'], 'client');
        $this->assertEquals($url['path'], '/callback');
        $this->assertEquals($query['state'], $state);

        // Have a look inside payload too.
        $payload = json_decode($this->decrypt($query['code']), true);
        $authCodeEntity = AuthCodeEntity::get()->filter('Code', $payload['auth_code_id'])->first();
        $this->assertEquals($payload['client_id'], $c->ClientIdentifier);
        $this->assertEquals($payload['user_id'], $m->ID);
        $this->assertNotNull($authCodeEntity);
    }

    public function testAccessToken()
    {
        $redir = 'http://client/callback';
        $c = $this->objFromFixture(ClientEntity::class, 'test');
        $m = $this->objFromFixture('Member', 'joe');
        $ac = $this->objFromFixture(AuthCodeEntity::class, 'test');

        // Make fake code.
        $payload = [
            'client_id' => $c->ClientIdentifier,
            'redirect_uri' => $redir,
            'auth_code_id' => $ac->Code,
            'scopes' => [],
            'user_id' => $m->ID,
            'expire_time' => strtotime('2099-06-06 12:00:00'),
            'code_challenge' => null,
            'code_challenge_method' => null,
        ];
        $authCode = $this->encrypt(json_encode($payload));

        $resp = $this->post('oauth/accessToken', [
            'client_id' => $c->ClientIdentifier,
            'client_secret' => $c->ClientSecret,
            'code' => $authCode,
            'grant_type' => 'authorization_code',
            'redirect_uri' => $redir,
        ]);

        $at = AccessTokenEntity::get()->last();

        $this->assertEquals(200, $resp->getStatusCode());

        $payload = json_decode($resp->getBody(), true);
        $this->assertTrue(is_int($payload['expires_in']));
        $this->assertTrue($this->tokenIsOk($payload['access_token']));

        // Unpack the token and poke around.
        $claims = $this->tokenGetClaims($payload['access_token']);
        $this->assertEquals($c->ClientIdentifier, $claims['aud']->getValue());
        $this->assertEquals($at->Code, $claims['jti']->getValue());
        $this->assertEquals($m->ID, $claims['sub']->getValue());
    }

    public function testAuthenticateRequest()
    {
        $c = $this->objFromFixture(ClientEntity::class, 'test');
        $m = $this->objFromFixture('Member', 'joe');
        $at = $this->objFromFixture(AccessTokenEntity::class, 'test');

        $jwt = (new Builder())
            ->setAudience($c->ClientIdentifier)
            ->setId($at->Code, true)
            ->setIssuedAt(time())
            ->setNotBefore(time())
            ->setExpiration(strtotime($at->Expiry))
            ->setSubject($m->ID)
            ->set('scopes', [])
            ->sign(new Sha256(), new Key(file_get_contents(__DIR__ . '/test.key')))
            ->getToken();

        $_SERVER['AUTHORIZATION'] = sprintf('Bearer %s', $jwt);

        $request = OauthServerController::authenticateRequest(null);

        $this->assertEquals($request->getAttribute('oauth_access_token_id'), $at->Code);
        $this->assertEquals($request->getAttribute('oauth_client_id'), $c->ClientIdentifier);
        $this->assertEquals($request->getAttribute('oauth_user_id'), $m->ID);
        $this->assertEquals($request->getAttribute('oauth_scopes'), []);
    }

    private function tokenIsOk($jwt)
    {
        $pk = new CryptKey(__DIR__ . '/test.crt');
        $token = (new Parser())->parse($jwt);
        return $token->verify(new Sha256(), $pk->getKeyPath());
    }

    private function tokenGetClaims($jwt)
    {
        return (new Parser())->parse($jwt)->getClaims();
    }
}

