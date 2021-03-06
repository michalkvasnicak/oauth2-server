<?php

namespace OAuth2\TokenIssuer;

use OAuth2\Storage\IAccessToken;
use OAuth2\Storage\IRefreshTokenStorage;

/**
 * @author Michal Kvasničák <michal.kvasnicak@mink.sk>
 */
class RefreshTokenIssuer 
{

    /** @var \OAuth2\Storage\IRefreshTokenStorage  */
    protected $refreshTokenStorage;


    public function __construct(IRefreshTokenStorage $refreshTokenStorage)
    {
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
        $scopes = $accessToken->getScopes();

        // in case of doctrine collections, etc
        if ($scopes instanceof \Traversable) {
            $scopes = iterator_to_array($scopes);
        }

        return $this->refreshTokenStorage->generate(
            $accessToken->getUser(),
            $accessToken->getClient(),
            $scopes
        );
    }

}
