<?php
/**
 * @author      Ian Simpson <ian@iansimpson.nz>
 * @copyright   Copyright (c) Ian Simpson
 */

namespace IanSimpson\Repositories;

use League\OAuth2\Server\Entities\RefreshTokenEntityInterface;
use League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface;
use IanSimpson\Entities\RefreshTokenEntity;

class RefreshTokenRepository implements RefreshTokenRepositoryInterface
{
    public function getRefreshToken($tokenId)
    {
        $clients = RefreshTokenEntity::get()->filter(array(
            'Code' => $tokenId,
        ));
        return $clients->first();
    }
    /**
     * {@inheritdoc}
     */
    public function persistNewRefreshToken(RefreshTokenEntityInterface $refreshToken)
    {
        /** @var RefreshTokenEntity $refreshTokenEntity */
        $refreshTokenEntity = $refreshToken;

        $refreshTokenEntity->Code = $refreshTokenEntity->getIdentifier();
        $refreshTokenEntity->write();
    }

    /**
     * {@inheritdoc}
     */
    public function revokeRefreshToken($tokenId)
    {
        // Some logic to revoke the refresh token in a database
        $token = $this->getRefreshToken($tokenId);
        $token->Revoked = true;
        $token->write();
    }

    /**
     * {@inheritdoc}
     */
    public function isRefreshTokenRevoked($tokenId)
    {
        $token = $this->getRefreshToken($tokenId);
        return (bool) $token->Revoked;
    }

    /**
     * {@inheritdoc}
     */
    public function getNewRefreshToken()
    {
        return new RefreshTokenEntity();
    }
}
