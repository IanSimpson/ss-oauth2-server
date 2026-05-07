<?php

namespace IanSimpson\Tests;

use DateInterval;
use DateTimeImmutable;
use IanSimpson\OAuth2\Repositories\AccessTokenRepository;
use JsonException;
use GuzzleHttp\Psr7\Query;
use IanSimpson\OAuth2\Entities\AccessTokenEntity;
use IanSimpson\OAuth2\Entities\AuthCodeEntity;
use IanSimpson\OAuth2\Entities\ClientEntity;
use IanSimpson\OAuth2\OauthServerController;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Validation\Constraint\IdentifiedBy;
use Lcobucci\JWT\Validation\Constraint\LooseValidAt;
use Lcobucci\JWT\Validation\Constraint\PermittedFor;
use Lcobucci\JWT\Validation\Constraint\RelatedTo;
use League\OAuth2\Server\AuthorizationValidators\AuthorizationValidatorInterface;
use League\OAuth2\Server\AuthorizationValidators\BearerTokenValidator;
use League\OAuth2\Server\CryptKey;
use League\OAuth2\Server\CryptKeyInterface;
use League\OAuth2\Server\CryptTrait;
use Monolog\Logger;
use PHPUnit\Framework\MockObject\MockObject;
use Psr\Clock\ClockInterface;
use Psr\Http\Message\ServerRequestInterface;
use SilverStripe\Core\Config\Config;
use SilverStripe\Core\Environment;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\Dev\FunctionalTest;
use SilverStripe\Security\Member;
use IanSimpson\Tests\Fixtures\BearerTokenValidatorFake;

/**
 * @internal
 *
 * @property-read string $encryptionKey
 */
class OauthServerControllerTest extends FunctionalTest
{
    use CryptTrait;

    /**
     * @var string|string[]
     */
    protected static $fixture_file = 'OauthServerControllerTest.yml';

    protected $autoFollowRedirection = false;

    /**
     * @var Logger|MockObject
     */
    private $logger;

    private const CODE_VERIFIER = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';

    private const CODE_CHALLENGE = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';

    /**
     * @var non-empty-string
     */
    private readonly string $publicKey;

    /**
     * @var non-empty-string
     */
    private readonly string $privateKey;

    protected function setUp(): void
    {
        parent::setUp();

        Config::nest();

        $_SERVER['SERVER_PORT'] = 80;

        $this->publicKey  = __DIR__ . '/public.key';
        $this->privateKey = __DIR__ . '/private.key';

        chmod($this->publicKey, 0600);
        chmod($this->privateKey, 0600);

        $this->setEncryptionKey(base64_encode(random_bytes(36)));

        Environment::putEnv('OAUTH_PUBLIC_KEY_PATH=' . $this->publicKey);
        Environment::putEnv('OAUTH_PRIVATE_KEY_PATH=' . $this->privateKey);
        Environment::putEnv('OAUTH_ENCRYPTION_KEY=' . $this->encryptionKey);

        $this->logger = $this->getMockBuilder(Logger::class)
            ->disableOriginalConstructor()
            ->getMock();

        Injector::inst()->registerService($this->logger, 'IanSimpson\\OAuth2\\Logger');

        // Remove all access tokens
        AccessTokenEntity::get()->removeAll();
    }

    protected function tearDown(): void
    {
        Config::unnest();

        parent::tearDown();
    }

    /**
     * @throws JsonException
     */
    public function testAuthorize(): void
    {
        $state = '789';

        /** @var ClientEntity $c */
        $c = $this->objFromFixture(ClientEntity::class, 'test');

        /** @var Member $m */
        $m = $this->objFromFixture(Member::class, 'joe');

        $this->logInAs($m->ID);

        $this->logger->expects($this->once())
            ->method('info')
            ->with($this->equalTo(
                'joe@joe.org authorised test (123) to access scopes "read_profile" on their behalf'
            ));

        $resp = $this->get(sprintf(
            'http://localhost/oauth/authorize?client_id=%s&redirect_uri=%s&response_type=code&scope=read_profile&state=%s&code_verifier=%s&code_challenge=%s',
            $c->ClientIdentifier,
            urlencode('http://client/callback'),
            $state,
            self::CODE_VERIFIER,
            self::CODE_CHALLENGE,
        ));

        $this->assertSame(302, $resp->getStatusCode());
        $url = parse_url($resp->getHeader('Location'));

        $this->assertIsArray($url);
        $this->assertArrayHasKey('query', $url);
        $this->assertArrayHasKey('host', $url);
        $this->assertArrayHasKey('path', $url);

        $query = Query::parse($url['query']);
        $this->assertSame($url['host'], 'client');
        $this->assertSame($url['path'], '/callback');
        $this->assertSame($query['state'], $state);

        // Have a look inside payload too.
        $payload = json_decode((string) $this->decrypt($query['code']), true, 512, JSON_THROW_ON_ERROR);

        $this->assertSame($payload['client_id'], $c->ClientIdentifier);
        $this->assertSame($payload['user_id'], (string)$m->ID);
        $this->assertNotEmpty($payload['auth_code_id']);

        /** @var AuthCodeEntity|null $authCodeEntity */
        $authCodeEntity = AuthCodeEntity::get()->filter('Code', $payload['auth_code_id'])->first();
        $this->assertInstanceOf(AuthCodeEntity::class, $authCodeEntity);
    }

    /**
     * @throws JsonException
     */
    public function testAccessTokenUserID(): void
    {
        /** @var ClientEntity $c */
        $c = $this->objFromFixture(ClientEntity::class, 'test');

        /** @var Member $m */
        $m = $this->objFromFixture(Member::class, 'joe');

        /** @var AuthCodeEntity $ac */
        $ac = $this->objFromFixture(AuthCodeEntity::class, 'test');

        // Make fake code.
        $payload = [
            'client_id'             => $c->ClientIdentifier,
            'redirect_uri'          => $c->ClientRedirectUri,
            'auth_code_id'          => $ac->Code,
            'scopes'                => [],
            'user_id'               => $m->ID,
            'expire_time'           => strtotime('2099-06-06 12:00:00'),
            'code_challenge'        => null,
            'code_challenge_method' => null,
        ];

        $authCode = $this->encrypt(json_encode($payload, JSON_THROW_ON_ERROR));

        $resp = $this->post('http://localhost/oauth/access_token/', [
            'client_id' => $c->ClientIdentifier,
            // Secret cannot be obtained from $c, at this point it's already hashed.
            'client_secret' => '456',
            'code'          => $authCode,
            'grant_type'    => 'authorization_code',
            'redirect_uri'  => $c->ClientRedirectUri,
        ]);

        /** @var AccessTokenEntity|null */
        $at = AccessTokenEntity::get()
            ->where([
                'ClientID' => $c->ID,
            ])
            ->last();

        $this->assertInstanceOf(AccessTokenEntity::class, $at);
        $this->assertSame(200, $resp->getStatusCode());

        $payload = json_decode($resp->getBody(), true, 512, JSON_THROW_ON_ERROR);

        $this->assertIsInt($payload['expires_in']);
        $this->assertIsString($payload['access_token']);
        $this->assertNotEmpty($at->Code);
        $this->assertNotEmpty($c->ClientIdentifier);
        $this->assertNotEmpty($m->ID);

        $configuration = Configuration::forSymmetricSigner(
            new Sha256(),
            InMemory::file($this->privateKey)
        );

        $constraints = [
            new IdentifiedBy($at->Code),
            new PermittedFor($c->ClientIdentifier),
            new RelatedTo((string) $m->ID),
            new LooseValidAt(new class implements ClockInterface {
                public function now(): DateTimeImmutable
                {
                    return new DateTimeImmutable();
                }
            }),
        ];

        $this->assertIsArray($payload);
        $this->assertArrayHasKey('access_token', $payload);

        $token = $configuration->parser()->parse($payload['access_token']);

        $this->assertTrue($configuration->validator()->validate($token, ...$constraints));

        // Now that we have a token, test if we can authenticate
        $at->setPrivateKey(new CryptKey($this->privateKey));
        $at->setExpiryDateTime((new DateTimeImmutable())->add(new DateInterval('PT10M')));

        $_SERVER['AUTHORIZATION'] = sprintf('Bearer %s', $at->toString());


        $request = OauthServerController::singleton()->authenticateRequest(null);

        $this->assertInstanceOf(ServerRequestInterface::class, $request);
        $this->assertSame($request->getAttribute('oauth_access_token_id'), $at->Code);
        $this->assertSame($request->getAttribute('oauth_client_id'), $c->ClientIdentifier);
        $this->assertSame($request->getAttribute('oauth_user_id'), (string) $m->ID);
        $this->assertSame($request->getAttribute('oauth_scopes'), []);
    }

    /**
     * @throws JsonException
     */
    public function testAccessTokenClientCredentials(): void
    {
        /** @var ClientEntity $c */
        $c = $this->objFromFixture(ClientEntity::class, 'test2');

        $resp = $this->post(
            'http://localhost/oauth/access_token/',
            [
                'grant_type'    => 'client_credentials'
            ],
            [
                'Content-Type' => 'application/x-www-form-urlencoded',
                'Authorization' => 'Basic ' . base64_encode($c->ClientIdentifier . ':' . '789'),
            ]
        );

        /** @var AccessTokenEntity|null */
        $at = AccessTokenEntity::get()
            ->where([
                'ClientID' => $c->ID,
            ])
            ->first();

        $this->assertInstanceOf(AccessTokenEntity::class, $at);
        $this->assertSame(200, $resp->getStatusCode());

        $payload = json_decode($resp->getBody(), true, 512, JSON_THROW_ON_ERROR);

        $this->assertIsInt($payload['expires_in']);
        $this->assertIsString($payload['access_token']);
        $this->assertNotEmpty($at->Code);
        $this->assertNotEmpty($c->ClientIdentifier);

        $configuration = Configuration::forSymmetricSigner(
            new Sha256(),
            InMemory::file($this->privateKey)
        );

        $constraints = [
            new IdentifiedBy($at->Code),
            new PermittedFor($c->ClientIdentifier),
            new LooseValidAt(new class implements ClockInterface {
                public function now(): DateTimeImmutable
                {
                    return new DateTimeImmutable();
                }
            }),
        ];

        $this->assertIsArray($payload);
        $this->assertArrayHasKey('access_token', $payload);

        $token = $configuration->parser()->parse($payload['access_token']);

        $this->assertTrue($configuration->validator()->validate($token, ...$constraints));

        // Now that we have a token, test if we can authenticate
        $resp = $this->post(
            'http://localhost/oauth/validate/',
            [],
            ['Authorization' => $token->toString()]
        );

        $this->assertSame(200, $resp->getStatusCode());
    }

    public function testGetGrantTypeExpiryInterval(): void
    {
        $oauthController = OauthServerController::singleton();
        OauthServerController::config()->merge('grant_expiry_interval', ['PT1H']);
        $this->assertSame('PT1H', $oauthController::getGrantTypeExpiryInterval()[0]);
    }

    public function testGetAuthorizationValidator(): void
    {
        // Default validator.
        $this->assertInstanceOf(
            BearerTokenValidator::class,
            OauthServerController::getAuthorizationValidator()
        );

        OauthServerController::setAuthorizationValidator(null);
        $this->assertInstanceOf(
            BearerTokenValidator::class,
            OauthServerController::getAuthorizationValidator()
        );

        // Set to custom validator.
        OauthServerController::setAuthorizationValidator(new BearerTokenValidatorFake());
        $this->assertInstanceOf(BearerTokenValidatorFake::class, OauthServerController::getAuthorizationValidator());
    }


    /**
     * @covers \IanSimpson\OAuth2\OauthServerController::createPrivateKey
     * @covers \IanSimpson\OAuth2\OauthServerController::createPublicKey
     */
    public function testCreateKeyFallsBackToCryptKeyWhenNoInjectorBinding(): void
    {
        $controller = new class extends OauthServerController {
            public function exposeCreatePrivateKey(string $path): CryptKeyInterface
            {
                return $this->createPrivateKey($path);
            }

            public function exposeCreatePublicKey(string $path): CryptKeyInterface
            {
                return $this->createPublicKey($path);
            }
        };

        $privateKey = $controller->exposeCreatePrivateKey($this->privateKey);
        $publicKey = $controller->exposeCreatePublicKey($this->publicKey);

        $this->assertInstanceOf(CryptKey::class, $privateKey);
        $this->assertInstanceOf(CryptKey::class, $publicKey);
    }

    /**
     * @covers \IanSimpson\OAuth2\OauthServerController::createPrivateKey
     * @covers \IanSimpson\OAuth2\OauthServerController::createPublicKey
     */
    public function testCreateKeyUsesInjectorBindingWhenConfigured(): void
    {
        $privatePath = $this->privateKey;
        $publicPath = $this->publicKey;

        // Create an anonymous custom CryptKey implementation
        $customKey = new class ($privatePath) implements CryptKeyInterface {
            private string $path;

            public function __construct(string $path)
            {
                $this->path = $path;
            }

            public function getKeyPath(): string
            {
                return $this->path;
            }

            public function getPassPhrase(): ?string
            {
                return null;
            }

            public function getKeyContents(): string
            {
                return (string) file_get_contents($this->path);
            }
        };

        $customClass = $customKey::class;

        // Register the custom class via Injector
        Injector::inst()->registerService(
            Injector::inst()->create($customClass, $privatePath),
            CryptKeyInterface::class
        );

        $controller = new class extends OauthServerController {
            public function exposeCreatePrivateKey(string $path): CryptKeyInterface
            {
                return $this->createPrivateKey($path);
            }

            public function exposeCreatePublicKey(string $path): CryptKeyInterface
            {
                return $this->createPublicKey($path);
            }
        };

        $privateKey = $controller->exposeCreatePrivateKey($privatePath);
        $publicKey = $controller->exposeCreatePublicKey($publicPath);

        $this->assertInstanceOf($customClass, $privateKey);
        $this->assertInstanceOf($customClass, $publicKey);

        // Clean up
        Injector::inst()->unregisterNamedObject(CryptKeyInterface::class);
    }
}
