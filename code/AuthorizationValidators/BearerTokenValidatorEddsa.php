<?php

namespace IanSimpson\OAuth2\AuthorizationValidators;

use DateTimeZone;
use Lcobucci\Clock\SystemClock;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Eddsa;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Validation\Constraint\LooseValidAt;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\RequiredConstraintsViolated;
use League\OAuth2\Server\AuthorizationValidators\BearerTokenValidator;
use League\OAuth2\Server\CryptKey;
use League\OAuth2\Server\CryptTrait;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use Psr\Http\Message\ServerRequestInterface;
use IanSimpson\OAuth2\Utility\Utility;

/**
 * Majority of logic was taken from {@link BearerTokenValidator} due to `$jwtConfiguration` property set to private
 * without any accessor methods available.
 *
 * An alternative would be to implement `AuthorizationValidatorInterface` but since most of the properties are almost
 * similar with `BearerTokenValidator`, extending the class makes sense.
 */
class BearerTokenValidatorEddsa extends BearerTokenValidator
{

    /**
     * @var Configuration
     */
    private $jwtConfiguration;

    private $accessTokenRepository;
    private $jwtValidAtDateLeeway;

    /**
     * @inheritDoc
     */
    public function __construct(AccessTokenRepositoryInterface $accessTokenRepository, \DateInterval $jwtValidAtDateLeeway = null)
    {
        $this->accessTokenRepository = $accessTokenRepository;
        $this->jwtValidAtDateLeeway = $jwtValidAtDateLeeway;
    }

    /**
     * @inheritDoc
     */
    public function setPublicKey(CryptKey $key)
    {
        $this->publicKey = $key;

        $this->initJwtConfiguration();
    }

    /**
     * @inheritDoc
     */
    public function validateAuthorization(ServerRequestInterface $request)
    {
        if ($request->hasHeader('authorization') === false) {
            throw OAuthServerException::accessDenied('Missing "Authorization" header');
        }

        $header = $request->getHeader('authorization');
        $jwt = \trim((string) \preg_replace('/^\s*Bearer\s/', '', $header[0]));

        try {
            // Attempt to parse the JWT
            $token = $this->jwtConfiguration->parser()->parse($jwt);
        } catch (\Lcobucci\JWT\Exception $exception) {
            throw OAuthServerException::accessDenied($exception->getMessage(), null, $exception);
        }

        try {
            // Attempt to validate the JWT
            $constraints = $this->jwtConfiguration->validationConstraints();
            $this->jwtConfiguration->validator()->assert($token, ...$constraints);
        } catch (RequiredConstraintsViolated $exception) {
            throw OAuthServerException::accessDenied('Access token could not be verified', null, $exception);
        }

        $claims = $token->claims();

        // Check if token has been revoked
        if ($this->accessTokenRepository->isAccessTokenRevoked($claims->get('jti'))) {
            throw OAuthServerException::accessDenied('Access token has been revoked');
        }

        // Return the request with additional attributes
        return $request
            ->withAttribute('oauth_access_token_id', $claims->get('jti'))
            ->withAttribute('oauth_client_id', $this->convertSingleRecordAudToString($claims->get('aud')))
            ->withAttribute('oauth_user_id', $claims->get('sub'))
            ->withAttribute('oauth_scopes', $claims->get('scopes'));
    }

    /**
     * Override this to use a different signer compatible with EdDSA algorithm
     */
    protected function initJwtConfiguration()
    {
        $this->jwtConfiguration = Configuration::forSymmetricSigner(
            new Eddsa(),
            InMemory::plainText('empty', 'empty')
        );

        $clock = new SystemClock(new DateTimeZone(\date_default_timezone_get()));

        // Extract PEM formatted key from generated public key
        $publicKeyResource = $this->publicKey->getKeyContents();

        // Extract the public key in DER format
        $derPublicKey = Utility::extractDERKeyValue($publicKeyResource);

        $this->jwtConfiguration->setValidationConstraints(
            new LooseValidAt($clock, $this->jwtValidAtDateLeeway),
            new SignedWith(
                new Eddsa(),
                InMemory::plainText($derPublicKey, $this->publicKey->getPassPhrase() ?? '')
            )
        );
    }

    /**
     * Convert single record arrays into strings to ensure backwards compatibility between v4 and v3.x of lcobucci/jwt
     *
     * @inheritDoc
     */
    private function convertSingleRecordAudToString($aud)
    {
        return \is_array($aud) && \count($aud) === 1 ? $aud[0] : $aud;
    }
}
