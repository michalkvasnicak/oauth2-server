<?php

namespace OAuth2\Security;

use OAuth2\Storage\IAccessToken;

/**
 * @author Michal Kvasničák <michal.kvasnicak@mink.sk>
 */
class Session 
{

    /** @var \OAuth2\Storage\IAccessToken  */
    protected $accessToken;

    public function __construct(IAccessToken $accessToken)
    {
        $this->accessToken = $accessToken;
    }


    /**
     * Gets access token associated with session
     * @return IAccessToken
     */
    public function getAccessToken()
    {
        return $this->accessToken;
    }


    /**
     * Gets users associated with current  access token (current authenticated user)
     *
     * @return \OAuth2\Storage\IUser
     */
    public function getUser()
    {
        return $this->getAccessToken()->getUser();
    }


    /**
     * Gets client associated with current access token
     *
     * @return \OAuth2\Storage\IClient
     */
    public function getClient()
    {
        return $this->getAccessToken()->getClient();
    }


    /**
     * Is allowed to operate under given scope?
     *
     * @param mixed $scope
     *
     * @return bool
     */
    public function isAllowed($scope)
    {
        return $this->getAccessToken()->hasScope($scope);
    }

}
