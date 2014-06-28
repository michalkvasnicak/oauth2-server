<?php

namespace OAuth2\Security;

use OAuth2\Storage\IClient;
use OAuth2\Storage\IScope;
use OAuth2\Storage\IUser;

/**
 * @author Michal Kvasničák <michal.kvasnicak@mink.sk>
 */
interface IAuthorizationSession 
{

    /**
     * Gets user associated with current session
     *
     * @return IUser
     */
    public function getUser();


    /**
     * Gets client associated with current session
     *
     * @return IClient
     */
    public function getClient();


    /**
     * Gets redirect uri (used in redirecting back to client)
     *
     * @return string
     */
    public function getRedirectUri();


    /**
     * Gets scopes for current authorization session
     *
     * @return IScope[]
     */
    public function getScopes();

}
