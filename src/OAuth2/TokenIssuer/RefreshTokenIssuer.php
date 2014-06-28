<?php

namespace OAuth2\TokenIssuer;

use OAuth2\Storage\IAccessToken;
use OAuth2\Storage\IRefreshTokenStorage;

/**
 * @author Michal Kvasničák <michal.kvasnicak@mink.sk>
 */
class RefreshTokenIssuer 
{

    /** @var int  */
    protected $lifetime;

    /** @var \OAuth2\Storage\IRefreshTokenStorage  */
    protected $refreshTokenStorage;


    public function __construct(IRefreshTokenStorage $refreshTokenStorage, $lifetime = 1209600)
    {
        $this->lifetime = (int) $lifetime;
        $this->refreshTokenStorage = $refreshTokenStorage;
    }


    /**
     * Issues refresh token for given access token
     *
     * @param IAccessToken $accessToken
     *
     * @return \OAuth2\Storage\IRefreshToken
     */
    public function issueToken(IAccessToken $accessToken)
    {
        return $this->refreshTokenStorage->generate(
            $accessToken->getUser(),
            $accessToken->getClient(),
            $accessToken->getScopes(),
            $this->lifetime
        );
    }

}
