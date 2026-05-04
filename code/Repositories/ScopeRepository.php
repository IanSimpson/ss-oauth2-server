<?php

/**
 * @author      Ian Simpson <ian@iansimpson.nz>
 * @copyright   Copyright (c) Ian Simpson
 */

namespace IanSimpson\OAuth2\Repositories;

use IanSimpson\OAuth2\Entities\ScopeEntity;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Entities\ScopeEntityInterface;
use League\OAuth2\Server\Repositories\ScopeRepositoryInterface;

class ScopeRepository implements ScopeRepositoryInterface
{
    /**
     * @return ScopeEntity|null
     */
    public function getScopeEntityByIdentifier($scopeIdentifier): ?ScopeEntityInterface
    {
        $scopes = ScopeEntity::get()->filter([
            'ScopeIdentifier' => $scopeIdentifier,
        ]);

        // @var ScopeEntity|null
        return $scopes->first();
    }

    public function finalizeScopes(
        array $scopes,
        string $grantType,
        ClientEntityInterface $clientEntity,
        ?string $userIdentifier = null,
        ?string $authCodeId = null
    ): array {
        return $scopes;
    }
}
