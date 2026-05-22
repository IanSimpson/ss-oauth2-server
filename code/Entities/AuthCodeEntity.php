<?php

/**
 * @author      Ian Simpson <ian@iansimpson.nz>
 * @copyright   Copyright (c) Ian Simpson
 */

namespace IanSimpson\OAuth2\Entities;

use DateTimeImmutable;
use League\OAuth2\Server\Entities\AuthCodeEntityInterface;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Entities\ScopeEntityInterface;
use League\OAuth2\Server\Entities\Traits\AuthCodeTrait;
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
 * @property ?string $MemberID
 *
 * @method ClientEntity               Client()
 * @method Member                     Member()
 * @method ManyManyList<ScopeEntity> ScopeEntities()
 */
class AuthCodeEntity extends DataObject implements AuthCodeEntityInterface
{
    use EntityTrait;
    use TokenEntityTrait;
    use AuthCodeTrait;

    /**
     * @config
     */
    private static string $table_name = 'OAuth_AuthCodeEntity';

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
     * @config
     *
     * @var array|string[]
     */
    private static array $has_one = [
        'Client' => ClientEntity::class,
        'Member' => Member::class,
    ];

    /**
     * @config
     *
     * @var array|string[]
     */
    private static array $many_many = [
        'ScopeEntities' => ScopeEntity::class,
    ];

    public function getIdentifier(): string
    {
        return (string) $this->Code;
    }

    public function getExpiryDateTime(): DateTimeImmutable
    {
        return (new DateTimeImmutable())->setTimestamp((int) $this->Expiry);
    }

    public function getUserIdentifier(): ?string
    {
        return $this->MemberID;
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
    public function setScopes($scopes): AuthCodeEntity
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
}
