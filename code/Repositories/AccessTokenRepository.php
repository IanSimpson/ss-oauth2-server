<?php
/**
 * @author      Ian Simpson <ian@iansimpson.nz>
 * @copyright   Copyright (c) Ian Simpson
 */

namespace IanSimpson\OAuth2\Repositories;

use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use IanSimpson\OAuth2\Entities\AccessTokenEntity;

class AccessTokenRepository implements AccessTokenRepositoryInterface
{
    public function getAccessToken($tokenId)
    {
        $clients = AccessTokenEntity::get()->filter([
            'Code' => $tokenId,
        ]);
        return $clients->first();
    }
    /**
     * {@inheritdoc}
     */
    public function persistNewAccessToken(AccessTokenEntityInterface $accessToken)
    {
        /** @var AccessTokenEntity $accessTokenEntity */
        $accessTokenEntity = $accessToken;
        $accessTokenEntity->Code = $accessTokenEntity->getIdentifier();
        $accessTokenEntity->write();
    }

    /**
     * {@inheritdoc}
     */
    public function revokeAccessToken($tokenId)
    {
        // Some logic here to revoke the access token
        $token = $this->getAccessToken($tokenId);
        $token->Revoked = true;
        $token->write();
    }

    /**
     * {@inheritdoc}
     */
    public function isAccessTokenRevoked($tokenId)
    {
        $token = $this->getAccessToken($tokenId);
        return (bool) $token->Revoked;
    }

    /**
     * {@inheritdoc}
     */
    public function getNewToken(ClientEntityInterface $clientEntity, array $scopes, $userIdentifier = null)
    {
        $accessToken = new AccessTokenEntity();
        $accessToken->setClient($clientEntity);
        foreach ($scopes as $scope) {
            $accessToken->addScope($scope);
        }
        $accessToken->setUserIdentifier($userIdentifier);

        return $accessToken;
    }
}
