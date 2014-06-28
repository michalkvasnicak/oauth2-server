<?php

namespace OAuth2\Storage;

/**
 * @author Michal Kvasničák <michal.kvasnicak@mink.sk>
 */
interface IToken 
{

    /**
     * Gets token identifier
     *
     * @return string
     */
    public function getId();


    /**
     * Gets user associated with this access token
     *
     * @return IUser
     */
    public function getUser();


    /**
     * Gets client associated with this access token
     *
     * @return IClient
     */
    public function getClient();


    /**
     * Gets associated scopes
     *
     * @return IScope[]
     */
    public function getScopes();


    /**
     * Has access token associated scope?
     *
     * @param mixed $scope
     *
     * @return bool
     */
    public function hasScope($scope);


    /**
     * Gets expiration time (timestamp)
     *
     * @return int
     */
    public function getExpiresAt();

}
