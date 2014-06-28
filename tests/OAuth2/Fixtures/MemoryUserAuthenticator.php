<?php

namespace tests\OAuth2\Fixtures;

use OAuth2\Security\IUserAuthenticator;
use OAuth2\Storage\IUser;

/**
 * @author Michal Kvasničák <michal.kvasnicak@mink.sk>
 */
class MemoryUserAuthenticator implements IUserAuthenticator
{

    /** @var User[] */
    protected $users = [];


    public function addUser(User $user)
    {
        $this->users[] = $user;
    }

    /**
     * Authenticates user and returns
     *
     * @param string $username
     * @param string $password
     *
     * @return IUser|null
     */
    public function authenticate($username, $password)
    {
        foreach ($this->users as $user) {
            if ($user->getUsername() === $username && $user->getPassword() === $password) {
                return $user;
            }
        }

        return null;
    }

}
 