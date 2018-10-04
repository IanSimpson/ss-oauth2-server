<?php
/**
 * @author      Ian Simpson <ian@iansimpson.nz>
 * @copyright   Copyright (c) Ian Simpson
 */

namespace IanSimpson\Repositories;

use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Repositories\ScopeRepositoryInterface;
use IanSimpson\Entities\ScopeEntity;

class ScopeRepository implements ScopeRepositoryInterface
{
    /**
     * {@inheritdoc}
     */
    public function getScopeEntityByIdentifier($scopeIdentifier)
    {
        $scopes = ScopeEntity::get()->filter(array(
            'ScopeIdentifier' => $scopeIdentifier,
        ));

        if (!sizeof($scopes)) {
            return;
        }

        $scope = $scopes->first();

        return $scope;
    }

    /**
     * {@inheritdoc}
     */
    public function finalizeScopes(
        array $scopes,
        $grantType,
        ClientEntityInterface $clientEntity,
        $userIdentifier = null
    ) {
        return $scopes;
    }
}
