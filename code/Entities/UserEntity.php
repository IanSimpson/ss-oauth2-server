<?php

/**
 * @author      Ian Simpson <ian@iansimpson.nz>
 * @copyright   Copyright (c) Ian Simpson
 */

namespace IanSimpson\OAuth2\Entities;

use League\OAuth2\Server\Entities\UserEntityInterface;
use SilverStripe\Security\Security;

class UserEntity implements UserEntityInterface
{
    /**
     * Return the user's identifier.
     */
    public function getIdentifier(): string
    {
        return (string)Security::getCurrentUser()?->ID;
    }
}
