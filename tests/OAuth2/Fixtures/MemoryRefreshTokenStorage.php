<?php

namespace tests\OAuth2\Fixtures;

use OAuth2\Storage\IClient;
use OAuth2\Storage\IRefreshToken;
use OAuth2\Storage\IRefreshTokenStorage;
use OAuth2\Storage\IScope;
use OAuth2\Storage\IUser;

/**
 * @author Michal Kvasničák <michal.kvasnicak@mink.sk>
 */
class MemoryRefreshTokenStorage extends ABaseTokenStorage implements IRefreshTokenStorage
{

    /**
     * Generates refresh token for given user, client, scopes and lifetime
     *
     * @param IUser $user
     * @param IClient $client
     * @param array|IScope[] $scopes
     *
     * @return IRefreshToken
     */
    public function generate(IUser $user = null, IClient $client, array $scopes = [])
    {
        $token = new RefreshToken(uniqid(), $user, $client, $scopes, time() + 60);
        return $token;
    }
}
 