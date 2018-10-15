<?php
/**
 * @author      Ian Simpson <ian@iansimpson.nz>
 * @copyright   Copyright (c) Ian Simpson
 */

namespace IanSimpson;

use Config;
use Exception;
use Injector;
use Member;
use function GuzzleHttp\Psr7\stream_for;
use IanSimpson\Entities;
use IanSimpson\Repositories;
use League\OAuth2\Server\Exception\OAuthServerException;
use Psr\Http\Message\ServerRequestInterface;

class OauthServerController extends \Controller
{
    private static $privateKey = '../private.key';
    private static $publicKey = '../public.key';
    private static $encryptionKey = '';

    protected $server;
    protected $myRequest;
    protected $myResponse;

    private $myRequestAdapter;
    private $myResponseAdapter;
    private $myRepositories;

    /**
     * @var LoggerInterface
     */
    protected $logger;

    /**
     * @var Authenticator classes on which to show an athentication greeting message.
     * @config
     */
    private static $authenticator_classes = [
        'MemberAuthenticator',
    ];

    private static $allowed_actions = array(
        'authorize',
        'accessToken',
    );

    private static $url_handlers = array(
        'authorize' 		=> 'authorize',
        'access_token'		=> 'accessToken',
    );

    public function __construct()
    {
        $privateKey = __DIR__.'/../../' . $this->config()->get('privateKey');

        $this->myRepositories = array(
            'client'		=> new Repositories\ClientRepository(),
            'scope'			=> new Repositories\ScopeRepository(),
            'accessToken'	=> new Repositories\AccessTokenRepository(),
            'authCode'		=> new Repositories\AuthCodeRepository(),
            'refreshToken'	=> new Repositories\RefreshTokenRepository(),
        );

        $encryptionKey = $this->config()->get('encryptionKey');
        if (empty($encryptionKey)) {
            throw new Exception('OauthServerController::encryptionKey must not be empty!');
        }

        //Muting errors with @ to stop notice about key permissions
        $this->server = @new \League\OAuth2\Server\AuthorizationServer(
            $this->myRepositories['client'],
            $this->myRepositories['accessToken'],
            $this->myRepositories['scope'],
            $privateKey,
            $encryptionKey
        );


        // Enable the authentication code grant on the server
        $grant = new \League\OAuth2\Server\Grant\AuthCodeGrant(
            $this->myRepositories['authCode'],
            $this->myRepositories['refreshToken'],
            new \DateInterval('PT10M') // authorization codes will expire after 10 minutes
        );
        $grant->setRefreshTokenTTL(new \DateInterval('P1M')); // refresh tokens will expire after 1 month
        $this->server->enableGrantType(
            $grant,
            new \DateInterval('PT1H') // access tokens will expire after 1 hour
        );

        // Enable the refresh code grant on the server
        $grant = new \League\OAuth2\Server\Grant\RefreshTokenGrant(
            $this->myRepositories['refreshToken']
        );
        $grant->setRefreshTokenTTL(new \DateInterval('P1M')); // new refresh tokens will expire after 1 month
        $this->server->enableGrantType(
            $grant,
            new \DateInterval('PT1H') // new access tokens will expire after 1 hour
        );

        $this->logger = Injector::inst()->get('OAuthLogger');

        parent::__construct();
    }

    public function handleRequest(\SS_HTTPRequest $request, \DataModel $model)
    {
        $this->myRequestAdapter = new Psr7\HttpRequestAdapter();
        $this->myRequest = $this->myRequestAdapter->toPsr7($request);

        $this->myResponseAdapter = new Psr7\HttpResponseAdapter();
        $this->myResponse = $this->myResponseAdapter->toPsr7($this->getResponse());

        return parent::handleRequest($request, $model);
    }

    public function authorize()
    {
        try {

            // Validate the HTTP request and return an AuthorizationRequest object.
            $authRequest = $this->server->validateAuthorizationRequest($this->myRequest);
            $client = $authRequest->getClient();
            $member = Member::currentUser();

            // The auth request object can be serialized and saved into a user's session.
            if (!$member || !$member->exists()) {
                // You will probably want to redirect the user at this point to a login endpoint.

                foreach ($this->config()->authenticator_classes as $authClass) {
                    $form = call_user_func([$authClass, 'get_login_form'], $this);
                    $form->sessionMessage(
                        _t(
                            'OAuth.AUTHENTICATE_MESSAGE',
                            'Please log in to access {originatingSite}.',
                            ['originatingSite' => $client->ClientName]
                        ),
                        'good'
                    );
                }

                return $this->redirect(
                        \Config::inst()->get('Security', 'login_url')
                    . "?BackURL=" . urlencode($_SERVER['REQUEST_URI'])
                );
            }

            // Once the user has logged in set the user on the AuthorizationRequest
            $authRequest->setUser(new Entities\UserEntity()); // an instance of UserEntityInterface

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
                implode(', ', array_map(function($entity) {
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
        } catch (\League\OAuth2\Server\Exception\OAuthServerException $exception) {
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
     * @return bool|ServerRequestInterface
     */
    public static function authenticateRequest($controller)
    {
        $publicKey = __DIR__.'/../../' . Config::inst()->get(self::class, 'publicKey');

        //Muting errors with @ to stop notice about key permissions
        $server = @new \League\OAuth2\Server\ResourceServer(
            new Repositories\AccessTokenRepository(),
            $publicKey
        );
        $request = \GuzzleHttp\Psr7\ServerRequest::fromGlobals();
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
        return \Member::get()->filter(array(
            "ID" => $request->getAttributes()['oauth_user_id']
        ))->first();
    }
}
