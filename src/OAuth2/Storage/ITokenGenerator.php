<?php

namespace OAuth2\Storage;

/**
 * @author Michal Kvasničák <michal.kvasnicak@mink.sk>
 */
interface ITokenGenerator extends ITemporaryGenerator
{

    /**
     * Generates refresh token for given user, client, scopes and lifetime
     *
     * @param IUser|null $user  user associated with token
     * @param IClient $client
     * @param array|IScope[] $scopes
     *
     * @return IRefreshToken|IAccessToken
     */
    public function generate(IUser $user = null, IClient $client, array $scopes = []);

}
