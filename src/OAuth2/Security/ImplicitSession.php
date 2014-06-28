<?php

namespace OAuth2\Security;

use OAuth2\Storage\IAccessToken;
use OAuth2\Storage\IScope;

/**
 * @author Michal Kvasničák <michal.kvasnicak@mink.sk>
 */
class ImplicitSession implements IAuthorizationSession
{

    /**
     * @var \OAuth2\Storage\IAccessToken
     */
    private $accessToken;

    /** @var string  */
    private $tokenTypeName;

    /** @var  string  */
    private $redirectUri;

    /**
     * @var null|string
     */
    private $state;


    public function __construct(
        IAccessToken $accessToken,
        $tokenTypeName,
        $redirectUri,
        $state = null
    ) {
        $this->accessToken = $accessToken;
        $this->tokenTypeName = $tokenTypeName;
        $this->redirectUri = $redirectUri;
        $this->state = $state;
    }


    /**
     * Gets state
     *
     * @return null|string
     */
    public function getState()
    {
        return $this->state;
    }


    /**
     * Gets access token
     *
     * @return IAccessToken
     */
    public function getAccessToken()
    {
        return $this->accessToken;
    }


    /**
     * Gets user associated with access token
     *
     * @return \OAuth2\Storage\IUser
     */
    public function getUser()
    {
        return $this->accessToken->getUser();
    }


    /**
     * Gets client associated with access token
     *
     * @return \OAuth2\Storage\IClient
     */
    public function getClient()
    {
        return $this->accessToken->getClient();
    }

    /**
     * Gets scopes for current authorization session
     *
     * @return IScope[]
     */
    public function getScopes()
    {
        return $this->accessToken->getScopes();
    }


    /**
     * Gets redirect uri (used in redirecting back to client)
     *
     * @return string
     */
    public function getRedirectUri()
    {
        $scopes = array_map(
            function(IScope $scope) {
                return $scope->getId();
            },
            $this->accessToken->getScopes()
        );

        $query = [
            'access_token' => $this->accessToken->getId(),
            'expires_in' => $this->accessToken->getExpiresAt() - time(),
            'token_type' => $this->tokenTypeName,
            'scope' => join(' ', $scopes)
        ];

        if ($this->state) {
            $query['state'] = $this->state;
        }

        ksort($query); // sort query params by key

        return $this->redirectUri . '#' . http_build_query($query);
    }

}
