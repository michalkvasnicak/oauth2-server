<?php

namespace OAuth2\Storage;

/**
 * @author Michal Kvasničák <michal.kvasnicak@mink.sk>
 */
interface IAuthorizationCode 
{

    /**
     * Gets authorization code id
     *
     * @return mixed
     */
    public function getId();


    /**
     * Gets expiration date in unix timestamp
     *
     * @return int
     */
    public function getExpiresAt();


    /**
     * Gets redirect uri associated with this code
     *
     * @return string|null
     */
    public function getRedirectUri();


    /**
     * Gets scopes associated with this code
     *
     * @return IScope[]
     */
    public function getScopes();


    /**
     * Gets user associated with this code
     *
     * @return IUser
     */
    public function getUser();


    /**
     * Gets client associated with this code
     *
     * @return IClient
     */
    public function getClient();


    /**
     * Gets state if was provided
     *
     * @return string|null
     */
    public function getState();

}
