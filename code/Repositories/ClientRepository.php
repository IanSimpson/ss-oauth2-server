<?php

/**
 * @author      Ian Simpson <ian@iansimpson.nz>
 * @copyright   Copyright (c) Ian Simpson
 */

namespace IanSimpson\OAuth2\Repositories;

use IanSimpson\OAuth2\Entities\ClientEntity;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;

class ClientRepository implements ClientRepositoryInterface
{
    public function getClientEntity($clientIdentifier): ?ClientEntityInterface
    {
        $clients = ClientEntity::get()->filter([
            'ClientIdentifier' => $clientIdentifier,
        ]);

        /** @var ClientEntity|null $client */
        $client = $clients->first();

        if (!$client instanceof ClientEntity) {
            return null;
        }

        $client->setConfidential();

        return $client;
    }

    /**
     * {@inheritDoc}
     */
    public function validateClient($clientIdentifier, $clientSecret, $grantType = null): bool
    {
        $client = $this->getClientEntity($clientIdentifier);

        // Validate the client secret and grant type
        return $client instanceof ClientEntity && $client->ClientConfidential
                                               && $client->isSecretValid((string) $clientSecret)
                                               && $grantType === $client->ClientGrantType;
    }
}
