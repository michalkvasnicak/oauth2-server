<?php

namespace OAuth2\Security;

use OAuth2\Storage\IUser;

/**
 * @author Michal Kvasničák <michal.kvasnicak@mink.sk>
 */
interface IUserAuthenticator 
{


    /**
     * Authenticates user and returns
     *
     * @param string $username
     * @param string $password
     *
     * @return IUser|null
     */
    public function authenticate($username, $password);

}
