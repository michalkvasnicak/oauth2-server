<?php

namespace OAuth2\Storage;

use OAuth2\GrantType\IGrantType;

/**
 * @author Michal Kvasničák <michal.kvasnicak@mink.sk>
 */
interface IClient 
{

    /**
     * Gets client identifier
     *
     * @return mixed
     */
    public function getId();


    /**
     * Gets client secret key (if is confidential)
     *
     * @return string|null
     */
    public function getSecret();


    /**
     * Gets scopes associated with client (which is allowed to access)
     *
     * @return IScope[]
     */
    public function getScopes();


    /**
     * Gets client owner (creator) if exists
     *
     * @return IUser|null
     */
    public function getOwner();


    /**
     * Gets client redirect uri
     *
     * @return string|null
     */
    public function getRedirectUri();


    /**
     * Is client allowed to use grant type?
     *
     * @param IGrantType $grantType
     *
     * @return bool
     */
    public function isAllowedToUse(IGrantType $grantType);

}
