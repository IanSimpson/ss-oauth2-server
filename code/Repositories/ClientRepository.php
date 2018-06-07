<?php
/**
 * @author      Ian Simpson <ian@iansimpson.nz>
 * @copyright   Copyright (c) Ian Simpson
 */

namespace IanSimpson\OAuth2\Repositories;

use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use IanSimpson\OAuth2\Entities\ClientEntity;

class ClientRepository implements ClientRepositoryInterface
{
    /**
     * {@inheritdoc}
     */
    public function getClientEntity($clientIdentifier, $grantType = null, $clientSecret = null, $mustValidateSecret = true)
    {
        $clients = ClientEntity::get()->filter([
            'ClientIdentifier' => $clientIdentifier,
        ]);

        // Check if client is registered
        if (!sizeof($clients)) {
            return;
        }

        $client = $clients->first();

        if ($mustValidateSecret === true
            && $client->ClientSecret != $clientSecret
        ) {
            return;
        }

        return $client;
    }
}
