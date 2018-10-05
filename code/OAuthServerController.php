<?php
/**
 * @author      Ian Simpson <ian@iansimpson.nz>
 * @copyright   Copyright (c) Ian Simpson
 */

namespace IanSimpson\OAuth2;

use DateInterval;
use Exception;
use GuzzleHttp\Psr7\ServerRequest;
use function GuzzleHttp\Psr7\stream_for;
use IanSimpson\OAuth2\Entities\UserEntity;
use IanSimpson\OAuth2\Repositories\AccessTokenRepository;
use IanSimpson\OAuth2\Repositories\AuthCodeRepository;
use IanSimpson\OAuth2\Repositories\ClientRepository;
use IanSimpson\OAuth2\Repositories\RefreshTokenRepository;
use IanSimpson\OAuth2\Repositories\ScopeRepository;
use League\OAuth2\Server\AuthorizationServer;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Grant\AuthCodeGrant;
use League\OAuth2\Server\Grant\RefreshTokenGrant;
use League\OAuth2\Server\ResourceServer;
use Psr\Http\Message\ServerRequestInterface;
use Robbie\Psr7\HttpRequestAdapter;
use Robbie\Psr7\HttpResponseAdapter;
use SilverStripe\Control\HTTPRequest;
use SilverStripe\Core\Config\Config;
use SilverStripe\Control\Controller;
use SilverStripe\Security\Member;
use Silverstripe\Security\Security;

class OauthServerController extends Controller
{
    private static $privateKey = '../private.key';
    private static $publicKey = '../public.key';
    private static $encryptionKey = '';

    private static $allowed_actions = [
        'authorize',
        'accessToken',
    ];

    private static $url_handlers = [
        'authorize'         => 'authorize',
        'access_token'      => 'accessToken',
    ];

    protected $server;
    protected $myRequest;
    protected $myResponse;

    private $myRequestAdapter;
    private $myResponseAdapter;
    private $myRepositories;

    public function __construct()
    {
        $privateKey = BASE_PATH . DIRECTORY_SEPARATOR . $this->config()->get('privateKey');

        $this->myRepositories = [
            'client'        => new ClientRepository(),
            'scope'         => new ScopeRepository(),
            'accessToken'   => new AccessTokenRepository(),
            'authCode'      => new AuthCodeRepository(),
            'refreshToken'  => new RefreshTokenRepository(),
        ];

        $encryptionKey = $this->config()->get('encryptionKey');
        if (empty($encryptionKey)) {
            throw new Exception('OauthServerController::encryptionKey must not be empty!');
        }

        // Muting errors with @ to stop notice about key permissions
        $this->server = @new AuthorizationServer(
            $this->myRepositories['client'],
            $this->myRepositories['accessToken'],
            $this->myRepositories['scope'],
            $privateKey,
            $encryptionKey
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
            new DateInterval('PT1H') // access tokens will expire after 1 hour
        );

        // Enable the refresh code grant on the server
        $grant = new RefreshTokenGrant(
            $this->myRepositories['refreshToken']
        );
        $grant->setRefreshTokenTTL(new DateInterval('P1M')); // new refresh tokens will expire after 1 month
        $this->server->enableGrantType(
            $grant,
            new DateInterval('PT1H') // new access tokens will expire after 1 hour
        );

        parent::__construct();
    }

    public function handleRequest(HTTPRequest $request)
    {
        $this->myRequestAdapter = new HttpRequestAdapter();
        $this->myRequest = $this->myRequestAdapter->toPsr7($request);

        $this->myResponseAdapter = new HttpResponseAdapter();
        $this->myResponse = $this->myResponseAdapter->toPsr7($this->getResponse());

        return parent::handleRequest($request);
    }

    public function authorize()
    {
        try {
            // Validate the HTTP request and return an AuthorizationRequest object.
            $authRequest = $this->server->validateAuthorizationRequest($this->myRequest);

            // The auth request object can be serialized and saved into a user's session.
            if (!Member::currentUserID()) {
                // You will probably want to redirect the user at this point to a login endpoint.

                return $this->redirect(Config::inst()->get(Security::class, 'login_url') . "?BackURL=" . urlencode($_SERVER['REQUEST_URI']));
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

            // Return the HTTP redirect response
            $this->myResponse = $this->server->completeAuthorizationRequest($authRequest, $this->myResponse);
        } catch (OAuthServerException $exception) {
            // All instances of OAuthServerException can be formatted into a HTTP response
            $this->myResponse = $exception->generateHttpResponse($this->myResponse);
        } catch (Exception $exception) {
            $this->myResponse = $this->myResponse->withStatus(500)->withBody(
                stream_for($exception->getMessage())
            );
        }

        return $this->myResponseAdapter->fromPsr7($this->myResponse);
    }

    public function accessToken()
    {
        try {
            // Try to respond to the request
            $this->myResponse = $this->server->respondToAccessTokenRequest($this->myRequest, $this->myResponse);
        } catch (OAuthServerException $exception) {
            // All instances of OAuthServerException can be formatted into a HTTP response
            $this->myResponse = $exception->generateHttpResponse($this->myResponse);
        } catch (Exception $exception) {
            $this->myResponse = $this->myResponse->withStatus(500)->withBody(
                stream_for($exception->getMessage())
            );
        }

        return $this->myResponseAdapter->fromPsr7($this->myResponse);
    }

    /**
     * @param $controller
     * @return bool|ServerRequestInterface
     */
    public static function authenticateRequest($controller)
    {
        $publicKey = BASE_PATH . DIRECTORY_SEPARATOR . Config::inst()->get(self::class, 'publicKey');

        //Muting errors with @ to stop notice about key permissions
        $server = @new ResourceServer(
            new AccessTokenRepository(),
            $publicKey
        );
        $request = ServerRequest::fromGlobals();
        $auth = $request->getHeader('Authorization');
        if ((!$auth || !sizeof($auth)) && $_SERVER['AUTHORIZATION']) {
            $request = $request->withAddedHeader('Authorization', $_SERVER['AUTHORIZATION']);
        }

        try {
            $request = $server->validateAuthenticatedRequest($request);
        } catch (Exception $exception) {
            return false;
        }
        return $request;
    }

    /**
     * @return bool|Member
     */
    public static function getMember($controller)
    {
        $request = self::authenticateRequest($controller);
        if (!$request) {
            return false;
        }
        $members = Member::get()->filter([
            "ID" => $request->getAttributes()['oauth_user_id']
        ]);
        /** @var Member $member */
        $member = $members->first();
        return $member;
    }
}
