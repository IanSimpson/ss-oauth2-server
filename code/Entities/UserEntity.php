<?php
/**
 * @author      Ian Simpson <ian@iansimpson.nz>
 * @copyright   Copyright (c) Ian Simpson
 */

namespace IanSimpson\OAuth2\Entities;

use League\OAuth2\Server\Entities\UserEntityInterface;
use SilverStripe\Security\Member;

class UserEntity implements UserEntityInterface
{
    /**
     * Return the user's identifier.
     *
     * @return mixed
     */
    public function getIdentifier()
    {
        return Member::currentUserID();
    }
}
