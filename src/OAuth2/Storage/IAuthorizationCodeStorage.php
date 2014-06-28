<?php

namespace OAuth2\Storage;

/**
 * @author Michal Kvasničák <michal.kvasnicak@mink.sk>
 */
interface IAuthorizationCodeStorage 
{


    /**
     * Gets authorization code
     *
     * @param string $code
     *
     * @return IAuthorizationCode|null
     */
    public function get($code);


    /**
     * Generates unique authorization code
     *
     * @param IUser $user
     * @param IClient $client
     * @param array $scopes
     * @param string $redirectUri
     * @param string|null $state    state provided to authorization
     *
     * @return IAuthorizationCode
     */
    public function generate(IUser $user, IClient $client, array $scopes = [], $redirectUri, $state = null);

}
