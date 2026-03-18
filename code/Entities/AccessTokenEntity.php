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
use Lcobucci\JWT\Token;
use League\OAuth2\Server\CryptKey;
use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Entities\ScopeEntityInterface;
use League\OAuth2\Server\Entities\Traits\AccessTokenTrait;
use League\OAuth2\Server\Entities\Traits\EntityTrait;
use League\OAuth2\Server\Entities\Traits\TokenEntityTrait;
use SilverStripe\ORM\DataObject;
use SilverStripe\ORM\ManyManyList;
use SilverStripe\Security\Member;

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
    use AccessTokenTrait {
        convertToJWT as defaultConvertToJWT;
    }
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
     * TODO: Update to CryptkeyInterface once `league/oauth2-server` is updated to `^9`
     */
    public function getPrivateKey(): ?CryptKey
    {
        return $this->privateKey;
    }

    /**
     * Generate a JWT from the access token
     *
     * @return Token
     */
    public function convertToJWT(): Token
    {
        $token = null;

        // Get token from extension (in case of different implementation than the default)
        $this->extend('updateJWT', $token);

        if ($token) {
            return $token;
        }

        // Default token generated
        return $this->defaultConvertToJWT();
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
        return (new DateTimeImmutable())->setTimestamp((int) $this->Expiry);
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
