<?php

namespace tests\OAuth2\Fixtures;

use OAuth2\Storage\IUser;

/**
 * @author Michal Kvasničák <michal.kvasnicak@mink.sk>
 */
class User implements IUser
{

    /**
     * @var null
     */
    private $username;

    /**
     * @var null
     */
    private $password;

    /** @var array  */
    private $scopes = [];


    public function __construct($username = null, $password = null, array $scopes = [])
    {
        $this->username = $username;
        $this->password = $password;
        $this->scopes = $scopes;
    }


    public function getUsername()
    {
        return $this->username;
    }


    public function getPassword()
    {
        return $this->password;
    }


    public function getScopes()
    {
        return $this->scopes;
    }

}
 