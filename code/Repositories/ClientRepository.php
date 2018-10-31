<?php
/**
 * @author      Ian Simpson <ian@iansimpson.nz>
 * @copyright   Copyright (c) Ian Simpson
 */

namespace IanSimpson\Repositories;

use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use IanSimpson\Entities\ClientEntity;

class ClientRepository implements ClientRepositoryInterface
{
    public function getClientEntity($clientIdentifier, $grantType, $clientSecret = null, $mustValidateSecret = true)
    {
        $clients = ClientEntity::get()->filter(array(
            'ClientIdentifier' => $clientIdentifier,
        ));

        // Check if client is registered
        if (!sizeof($clients)) {
            return null;
        }

        /** @var ClientEntity $client */
        $client = $clients->first();

        if (
            $mustValidateSecret === true
            && !$client->isSecretValid($clientSecret)
        ) {
            return null;
        }

        return $client;
    }
}
