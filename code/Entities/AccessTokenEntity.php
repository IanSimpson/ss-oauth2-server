<?php

/**
 * @author      Ian Simpson <ian@iansimpson.nz>
 * @copyright   Copyright (c) Ian Simpson
 */

namespace IanSimpson\OAuth2\Entities;

use DateTimeImmutable;
use Exception;
use Lcobucci\JWT\Token;
use League\OAuth2\Server\CryptKeyInterface;
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

    public function getPrivateKey(): ?CryptKeyInterface
    {
        return $this->privateKey;
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

    public function setIdentifier(mixed $code): void
    {
        $this->Code = (string) $code;
    }

    public function setExpiryDateTime(DateTimeImmutable $expiry): void
    {
        $this->Expiry = $expiry->getTimestamp();
    }

    public function setUserIdentifier(mixed $id): void
    {
        $this->MemberID = (int) $id;
    }

    public function addScope(ScopeEntityInterface $scope): void
    {
        $this->ScopeEntities()->add($scope);
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

    public function setClient(ClientEntityInterface $client): void
    {
        $this->ClientID = $client->ID;
    }

    /**
     * Generate a string representation from the access token
     */
    public function toString(): string
    {
        $token = null;

        // Get token from extension (in case of different implementation than the default)
        $this->extend('updateJWT', $token);

        if ($token) {
            return $token->toString();
        }

        return $this->convertToJWT()->toString();
    }
}
