<?php

namespace tests\OAuth2\Fixtures;

use OAuth2\Storage\IAuthorizationCode;
use OAuth2\Storage\IAuthorizationCodeStorage;
use OAuth2\Storage\IClient;
use OAuth2\Storage\IUser;

/**
 * @author Michal Kvasničák <michal.kvasnicak@mink.sk>
 */
class MemoryAuthorizationCodeStorage implements IAuthorizationCodeStorage
{

    protected $codes = [];


    /**
     * Gets authorization code
     *
     * @param string $code
     *
     * @return IAuthorizationCode|null
     */
    public function get($code)
    {
        return isset($this->codes[$code]) ? $this->codes[$code] : null;
    }

    /**
     * Sets lifetime for generator
     *
     * @param int $lifetime
     */
    public function setLifetime($lifetime)
    {
        // TODO: Implement setLifetime() method.
    }


    /**
     * @param IUser $user
     * @param IClient $client
     * @param array $scopes
     * @param string $redirectUri
     * @param null|string $state
     *
     * @return IAuthorizationCode|AuthorizationCode
     */
    public function generate(IUser $user, IClient $client, array $scopes = [], $redirectUri, $state = null)
    {
        $id = uniqid();

        return $this->codes[$id] = new AuthorizationCode(
            $id,
            $user,
            $client,
            $scopes,
            $redirectUri,
            $state,
            time() + 100
        );
    }
}
 