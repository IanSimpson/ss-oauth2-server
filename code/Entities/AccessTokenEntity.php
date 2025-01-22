<?php

/**
 * @author      Ian Simpson <ian@iansimpson.nz>
 * @copyright   Copyright (c) Ian Simpson
 */

namespace IanSimpson\OAuth2\Entities;

use DateInterval;
use DateTimeImmutable;
use Exception;
use IanSimpson\OAuth2\OauthServerController;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Eddsa;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Token;
use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Entities\ScopeEntityInterface;
use League\OAuth2\Server\Entities\Traits\AccessTokenTrait;
use League\OAuth2\Server\Entities\Traits\EntityTrait;
use League\OAuth2\Server\Entities\Traits\TokenEntityTrait;
use SilverStripe\ORM\DataObject;
use SilverStripe\ORM\ManyManyList;
use SilverStripe\Security\Member;
use Lcobucci\JWT\Builder;
use League\OAuth2\Server\CryptKey;
use IanSimpson\OAuth2\Utility\Utility;

/**
 * @property ?string $Code
 * @property int $Expiry
 * @property bool $Revoked
 * @property int $ClientID
 * @property int $MemberID
 * @method ClientEntity Client()
 * @method Member Member()
 * @method ManyManyList|ScopeEntity[] ScopeEntities()
 */
class AccessTokenEntity extends DataObject implements AccessTokenEntityInterface
{
    use AccessTokenTrait;
    use TokenEntityTrait;
    use EntityTrait;

    /**
     * @config
     */
    private static string $table_name = 'OAuth_AccessTokenEntity';

    /**
     * @var array|string[]
     *
     * @config
     */
    private static array $db = [
        'Code'    => 'Text',
        'Expiry'  => 'Datetime',
        'Revoked' => 'Boolean',
    ];

    /**
     * @var array|string[]
     *
     * @config
     */
    private static array $has_one = [
        'Client' => ClientEntity::class,
        'Member' => Member::class,
    ];

    /**
     * @var array|string[]
     *
     * @config
     */
    private static array $many_many = [
        'ScopeEntities' => ScopeEntity::class,
    ];

    /**
     *
     * @var string[]
     *
     * @config
     */
    private static array $searchable_fields = [
        'Code',
    ];

    /**
     * Generate a JWT from the access token
     *
     * @return Token
     */
    public function convertToJWT()
    {
        // Extract the PEM key generated
        $pemPrivateKey = $this->privateKey->getKeyContents();

        // Extract the DER formatted key to use as seed for generating the private/secret key
        $derKey = Utility::extractDERKeyValue($pemPrivateKey);

        // Generate the secret key via Sodium library
        $secretkey = sodium_crypto_sign_secretkey(sodium_crypto_sign_seed_keypair($derKey));

        // Configure the JWT generation
        $config = Configuration::forAsymmetricSigner(
            new Eddsa(),
            InMemory::plainText($secretkey),
            InMemory::plainText('empty', 'empty')
        );

        // return the token
        return $config->builder()
            ->permittedFor($this->getClient()->getIdentifier())
            ->identifiedBy($this->getIdentifier())
            ->issuedAt(new DateTimeImmutable())
            ->canOnlyBeUsedAfter(new DateTimeImmutable())
            ->expiresAt($this->getExpiryDateTime())
            ->relatedTo((string) $this->getUserIdentifier())
            ->withClaim('scopes', $this->getScopes())
            ->getToken($config->signer(), $config->signingKey());
    }

    public function getIdentifier(): string
    {
        return (string) $this->Code;
    }

    /**
     * @throws Exception
     */
    public function getExpiryDateTime(): DateTimeImmutable
    {
        return (new DateTimeImmutable())->setTimestamp((int) $this->Expiry)
            ->add(new DateInterval(OauthServerController::getGrantTypeExpiryInterval()));
    }

    public function getUserIdentifier(): string
    {
        return (string) $this->MemberID;
    }

    public function getScopes(): array
    {
        return $this->ScopeEntities()->toArray();
    }

    /**
     * @return ClientEntity
     */
    public function getClient(): ClientEntityInterface
    {
        return $this->Client();
    }

    public function setIdentifier(mixed $code): self
    {
        $this->Code = (string) $code;

        return $this;
    }

    public function setExpiryDateTime(DateTimeImmutable $expiry): self
    {
        $this->Expiry = $expiry->getTimestamp();

        return $this;
    }

    public function setUserIdentifier(mixed $id): self
    {
        $this->MemberID = (int) $id;

        return $this;
    }

    public function addScope(ScopeEntityInterface $scope): self
    {
        if ($scope instanceof ScopeEntity) {
            $this->ScopeEntities()->add($scope);
        }

        return $this;
    }

    /**
     * @param ScopeEntity[] $scopes
     */
    public function setScopes($scopes): self
    {
        $this->ScopeEntities()->removeAll();

        foreach ($scopes as $scope) {
            $this->addScope($scope);
        }

        return $this;
    }

    public function setClient(ClientEntityInterface $client): self
    {
        if ($client instanceof ClientEntity) {
            $this->ClientID = $client->ID;
        }

        return $this;
    }
}
