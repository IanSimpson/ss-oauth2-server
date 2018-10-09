<?php
/**
 * @author      Ian Simpson <ian@iansimpson.nz>
 * @copyright   Copyright (c) Ian Simpson
 */

namespace IanSimpson\Repositories;

use League\OAuth2\Server\Entities\AuthCodeEntityInterface;
use League\OAuth2\Server\Repositories\AuthCodeRepositoryInterface;
use IanSimpson\Entities\AuthCodeEntity;

class AuthCodeRepository implements AuthCodeRepositoryInterface
{
    public function getAuthCode($codeId)
    {
        $codes = AuthCodeEntity::get()->filter(array(
            'Code' => $codeId,
        ));
        return $codes->first();
    }
    /**
     * {@inheritdoc}
     */
    public function persistNewAuthCode(AuthCodeEntityInterface $authCode)
    {
        /** @var AuthCodeEntity $authCodeEntity */
        $authCodeEntity = $authCode;

        $authCodeEntity->Code = $authCodeEntity->getIdentifier();
        $authCodeEntity->write();
    }

    /**
     * {@inheritdoc}
     */
    public function revokeAuthCode($codeId)
    {
        // Some logic to revoke the auth code in a database
        $code = $this->getAuthCode($codeId);
        $code->Revoked = true;
        $code->write();
    }

    /**
     * {@inheritdoc}
     */
    public function isAuthCodeRevoked($codeId)
    {
        $code = $this->getAuthCode($codeId);
        return (bool) $code->Revoked;
    }

    /**
     * {@inheritdoc}
     */
    public function getNewAuthCode()
    {
        return new AuthCodeEntity();
    }
}
