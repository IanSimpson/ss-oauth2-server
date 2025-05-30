<?php

/**
 * @author      Ian Simpson <ian@iansimpson.nz>
 * @copyright   Copyright (c) Ian Simpson
 */

namespace IanSimpson\OAuth2;

use DateInterval;
use Exception;
use GuzzleHttp\Psr7\Response;
use GuzzleHttp\Psr7\ServerRequest;
use GuzzleHttp\Psr7\Utils;
use IanSimpson\OAuth2\Entities\UserEntity;
use IanSimpson\OAuth2\Entities\ClientEntity;
use IanSimpson\OAuth2\Entities\ScopeEntity;
use IanSimpson\OAuth2\Repositories\AccessTokenRepository;
use IanSimpson\OAuth2\Repositories\AuthCodeRepository;
use IanSimpson\OAuth2\Repositories\ClientRepository;
use IanSimpson\OAuth2\Repositories\RefreshTokenRepository;
use IanSimpson\OAuth2\Repositories\ScopeRepository;
use League\OAuth2\Server\AuthorizationServer;
use League\OAuth2\Server\Entities\ScopeEntityInterface;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Grant\AuthCodeGrant;
use League\OAuth2\Server\Grant\ClientCredentialsGrant;
use League\OAuth2\Server\Grant\RefreshTokenGrant;
use League\OAuth2\Server\ResourceServer;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Log\LoggerInterface;
use Robbie\Psr7\HttpRequestAdapter;
use Robbie\Psr7\HttpResponseAdapter;
use SilverStripe\Control\Controller;
use SilverStripe\Control\HTTPRequest;
use SilverStripe\Control\HTTPResponse;
use SilverStripe\Core\Config\Config;
use SilverStripe\Core\Environment;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\ORM\ValidationResult;
use SilverStripe\Security\Member;
use SilverStripe\Security\Security;
use IanSimpson\OAuth2\AuthorizationValidators\BearerTokenValidatorEddsa;

class OauthServerController extends Controller
{
    /**
     * @var string default is 1 hour
     *
     * @config
     */
    public static string $grant_expiry_interval = 'PT1H';

    /**
     * @var AuthorizationServer
     */
    protected $server;

    /**
     * @var ServerRequestInterface
     */
    protected $myRequest;

    /**
     * @var ResponseInterface
     */
    protected $myResponse;

    /**
     * @var LoggerInterface
     */
    protected $logger;

    private readonly string $privateKey;

    private readonly string $publicKey;

    private readonly string $encryptionKey;

    /**
     * @var string[]
     *
     * @config
     */
    private static array $allowed_actions = [
        'authorize',
        'accessToken',
        'validateClientGrant',
    ];

    /**
     * @var string[]
     *
     * @config
     */
    private static array $url_handlers = [
        'authorize'         => 'authorize',
        'access_token'      => 'accessToken',
        'oauth_logon'       => 'logon',
        'validate'          => 'validateClientGrant',
    ];

    private HttpRequestAdapter $myRequestAdapter;

    private HttpResponseAdapter $myResponseAdapter;

    /**
     * @var array{client: ClientRepository, scope: ScopeRepository, accessToken: AccessTokenRepository, authCode: AuthCodeRepository, refreshToken: RefreshTokenRepository}
     */
    private array $myRepositories;

    /**
     * @throws Exception
     */
    public function __construct()
    {
        if (!self::hasKey('OAUTH_PRIVATE_KEY_PATH')) {
            throw new Exception('OauthServerController::$privateKey must not be empty!');
        }

        if (!self::hasKey('OAUTH_PUBLIC_KEY_PATH')) {
            throw new Exception('OauthServerController::$publicKey must not be empty!');
        }

        if (!self::hasKey('OAUTH_ENCRYPTION_KEY')) {
            throw new Exception('OauthServerController::$encryptionKey must not be empty!');
        }

        $this->privateKey = self::getKey('OAUTH_PRIVATE_KEY_PATH');
        $this->publicKey  = self::getKey('OAUTH_PUBLIC_KEY_PATH');
        $this->encryptionKey = self::getKey('OAUTH_ENCRYPTION_KEY');

        $this->myRepositories = [
            'client'        => new ClientRepository(),
            'scope'         => new ScopeRepository(),
            'accessToken'   => new AccessTokenRepository(),
            'authCode'      => new AuthCodeRepository(),
            'refreshToken'  => new RefreshTokenRepository(),
        ];

        // Will fail ungracefully if key(s) permissions are not set to 0600|0660
        $this->server = new AuthorizationServer(
            $this->myRepositories['client'],
            $this->myRepositories['accessToken'],
            $this->myRepositories['scope'],
            $this->privateKey,
            $this->encryptionKey
        );

        // Enable the authentication code grant on the server
        $grant = new AuthCodeGrant(
            $this->myRepositories['authCode'],
            $this->myRepositories['refreshToken'],
            new DateInterval('PT10M') // authorization codes will expire after 10 minutes
        );
        $grant->setRefreshTokenTTL(new DateInterval('P1M')); // refresh tokens will expire after 1 month
        $this->server->enableGrantType(
            $grant,
            new DateInterval(self::getGrantTypeExpiryInterval())
        );

        // Enable the refresh code grant on the server
        $grant = new RefreshTokenGrant(
            $this->myRepositories['refreshToken']
        );
        $grant->setRefreshTokenTTL(new DateInterval('P1M')); // new refresh tokens will expire after 1 month
        $this->server->enableGrantType(
            $grant,
            new DateInterval(self::getGrantTypeExpiryInterval())
        );

        // Enable Client credentials grant
        $grant = new ClientCredentialsGrant();
        $this->server->enableGrantType(
            $grant,
            new DateInterval(self::getGrantTypeExpiryInterval())
        );

        // Setup logger
        $this->logger = Injector::inst()->get('IanSimpson\\OAuth2\\Logger'); // @phpstan-ignore-line

        // Setup adapters, these will be reset on handleRequest()
        $this->myRequestAdapter = new HttpRequestAdapter();

        parent::__construct();
    }

    public static function getGrantTypeExpiryInterval(): mixed
    {
        return self::config()->grant_expiry_interval ?? self::$grant_expiry_interval;
    }

    public function handleRequest(HTTPRequest $request): HTTPResponse
    {
        $this->myRequestAdapter = new HttpRequestAdapter();
        $this->myRequest        = $this->myRequestAdapter->toPsr7($request);

        $this->myResponseAdapter = new HttpResponseAdapter();
        $this->myResponse        = $this->myResponseAdapter->toPsr7($this->getResponse());

        return parent::handleRequest($request);
    }

    public function authorize(): HTTPResponse
    {
        try {
            // Validate the HTTP request and return an AuthorizationRequest object.
            $authRequest = $this->server->validateAuthorizationRequest($this->myRequest);

            /** @var ClientEntity $client */
            $client = $authRequest->getClient();
            $member = Security::getCurrentUser();

            // The auth request object can be serialized and saved into a user's session.
            if (!$member instanceof Member || !$member->exists()) {
                // You will probably want to redirect the user at this point to a login endpoint.

                Security::singleton()->setSessionMessage(
                    _t(
                        'OAuth.AUTHENTICATE_MESSAGE',
                        'Please log in to access {originatingSite}.',
                        ['originatingSite' => $client->ClientName]
                    ),
                    ValidationResult::TYPE_GOOD
                );

                return $this->redirect(Config::inst()->get(Security::class, 'login_url') . '?BackURL=' . urlencode($_SERVER['REQUEST_URI']));
            }

            // Once the user has logged in set the user on the AuthorizationRequest
            $authRequest->setUser(new UserEntity()); // an instance of UserEntityInterface

            // At this point you should redirect the user to an authorization page.
            // This form will ask the user to approve the client and the scopes requested.

            // TODO Implement authorisation step. For now, authorize implicitly, this is fine if you don't use scopes,
            // and everything falls into one global bucket, e.g. when you have only one resource endpoint.

            // Once the user has approved or denied the client update the status
            // (true = approved, false = denied)
            $authRequest->setAuthorizationApproved(true);

            $this->logger->info(sprintf(
                '%s authorised %s (%s) to access scopes "%s" on their behalf',
                $member->Email,
                $client->ClientName,
                $client->ClientIdentifier,
                implode(', ', array_map(static function (ScopeEntityInterface $entity): mixed {
                    if (!$entity instanceof ScopeEntity) {
                        return null;
                    }

                    return $entity->ScopeIdentifier;
                }, $authRequest->getScopes()))
            ));

            // Return the HTTP redirect response
            $this->myResponse = $this->server->completeAuthorizationRequest($authRequest, $this->myResponse);
        } catch (OAuthServerException $exception) {
            // All instances of OAuthServerException can be formatted into a HTTP response
            $this->myResponse = $exception->generateHttpResponse($this->myResponse);
        } catch (Exception $exception) {
            $this->myResponse = $this->myResponse->withStatus(500)->withBody(
                Utils::streamFor($exception->getMessage())
            );
        }

        return $this->myResponseAdapter->fromPsr7($this->myResponse);
    }

    public function accessToken(): HTTPResponse
    {
        try {
            // Try to respond to the request
            $this->myResponse = $this->server->respondToAccessTokenRequest($this->myRequest, $this->myResponse);
        } catch (OAuthServerException $exception) {
            // All instances of OAuthServerException can be formatted into a HTTP response
            $this->myResponse = $exception->generateHttpResponse($this->myResponse);
        }

        return $this->myResponseAdapter->fromPsr7($this->myResponse);
    }

    /**
     * @param mixed $controller
     */
    public static function authenticateRequest($controller): ?ServerRequestInterface
    {
        $publicKey = self::getKey('OAUTH_PUBLIC_KEY_PATH');

        $server = new ResourceServer(
            new AccessTokenRepository(),
            $publicKey,
            new BearerTokenValidatorEddsa(new AccessTokenRepository())
        );

        $request = ServerRequest::fromGlobals();

        if (!$request->hasHeader('authorization') && isset($_SERVER['AUTHORIZATION'])) {
            $request = $request->withAddedHeader('authorization', $_SERVER['AUTHORIZATION']);
        }

        try {
            $request = $server->validateAuthenticatedRequest($request);
        } catch (OAuthServerException) {
            return null;
        }

        return $request;
    }

    /**
     * @param mixed $controller
     */
    public static function getMember($controller): ?Member
    {
        $request = self::authenticateRequest($controller);

        if (!$request instanceof ServerRequestInterface) {
            return null;
        }

        $members = Member::get()->filter([
            'ID' => $request->getAttributes()['oauth_user_id'],
        ]);

        // @var Member
        return $members->first();
    }

    public function validateClientGrant(HTTPRequest $request): HTTPResponse
    {
        $server = new ResourceServer(
            new AccessTokenRepository(),
            $this->publicKey,
            new BearerTokenValidatorEddsa(new AccessTokenRepository())
        );

        $this->handleRequest($request);

        try {
            $server->validateAuthenticatedRequest($this->myRequest);
        } catch (OAuthServerException $e) {
            return $this->myResponseAdapter->fromPsr7($e->generateHttpResponse(new Response()));
        }

        return new HTTPResponse('', 200);
    }

    private static function getKey(string $key): string
    {
        return Environment::getEnv($key);
    }

    private static function hasKey(string $key): bool
    {
        return Environment::hasEnv($key) && Environment::getEnv($key) !== '';
    }
}
