<?php

namespace tests\OAuth2\Fixtures;

use OAuth2\Storage\IAccessToken;
use OAuth2\Storage\IAccessTokenStorage;
use OAuth2\Storage\IClient;
use OAuth2\Storage\IScope;
use OAuth2\Storage\IUser;

/**
 * @author Michal Kvasničák <michal.kvasnicak@mink.sk>
 */
class MemoryAccessTokenStorage extends ABaseTokenStorage implements IAccessTokenStorage
{

    /**
     * Generates refresh token for given user, client, scopes and lifetime
     *
     * @param IUser $user
     * @param IClient $client
     * @param array|IScope[] $scopes
     *
     * @return IAccessToken
     */
    public function generate(IUser $user = null, IClient $client, array $scopes = [])
    {
        $token = new AccessToken(uniqid(), $user, $client, $scopes, time() + 60);
        return $token;
    }
}
 