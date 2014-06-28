<?php

namespace OAuth2\Security;

use OAuth2\Storage\IAuthorizationCode;

/**
 * @author Michal Kvasničák <michal.kvasnicak@mink.sk>
 */
class AuthorizationCodeSession implements IAuthorizationSession
{


    /**
     * @var \OAuth2\Storage\IAuthorizationCode
     */
    private $authorizationCode;


    public function __construct(IAuthorizationCode $authorizationCode)
    {
        $this->authorizationCode = $authorizationCode;
    }

    /**
     * Gets client from current session
     *
     * @return \OAuth2\Storage\IClient
     */
    public function getClient()
    {
        return $this->authorizationCode->getClient();
    }


    /**
     * Gets user from current session
     *
     * @return \OAuth2\Storage\IUser
     */
    public function getUser()
    {
        return $this->authorizationCode->getUser();
    }


    /**
     * Gets authorization code from current session
     *
     * @return IAuthorizationCode
     */
    public function getAuthorizationCode()
    {
        return $this->authorizationCode;
    }


    /**
     * Gets redirect uri (used in redirecting back to client)
     *
     * @return null|string
     */
    public function getRedirectUri()
    {
        // find ? in redirect uri and determine if is last character
        // if not, we assume that there are query params so we add &
        // otherwise just add http query params
        $uri = $this->authorizationCode->getRedirectUri();
        $state = $this->authorizationCode->getState();
        $query = strpos($uri, '?');

        if ($query === false) {
            $uri .= '?';
        } else if ($query !== strlen($uri) - 1) {
            $uri .= '&';
        }

        return $uri . http_build_query(
            ['code' => $this->authorizationCode->getId()] + ($state ? ['state' => $state] : [])
        );
    }


    /**
     * Gets scopes from authorization code
     *
     * @return \OAuth2\Storage\IScope[]
     */
    public function getScopes()
    {
        return $this->authorizationCode->getScopes();
    }


    /**
     * Gets state used in authorization
     *
     * @return null|string
     */
    public function getState()
    {
        return $this->authorizationCode->getState();
    }

}
