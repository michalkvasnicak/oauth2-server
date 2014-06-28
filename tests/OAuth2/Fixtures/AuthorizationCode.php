<?php

namespace tests\OAuth2\Fixtures;

use OAuth2\Storage\IAuthorizationCode;
use OAuth2\Storage\IClient;
use OAuth2\Storage\IScope;
use OAuth2\Storage\IUser;

/**
 * @author Michal Kvasničák <michal.kvasnicak@mink.sk>
 */
class AuthorizationCode implements IAuthorizationCode
{


    /**
     * @var
     */
    private $id;

    /**
     * @var \OAuth2\Storage\IUser
     */
    private $user;

    /**
     * @var \OAuth2\Storage\IClient
     */
    private $client;

    /**
     * @var array
     */
    private $scopes;

    /**
     * @var
     */
    private $redirectUri;

    /**
     * @var
     */
    private $expiresAt;

    /**
     * @var null
     */
    private $state;

    public function __construct($id, IUser $user, IClient $client, array $scopes = [], $redirectUri, $state = null, $expiresAt)
    {
        $this->id = $id;
        $this->user = $user;
        $this->client = $client;
        $this->scopes = $scopes;
        $this->redirectUri = $redirectUri;
        $this->expiresAt = $expiresAt;
        $this->state = $state;
    }

    /**
     * Gets authorization code id
     *
     * @return mixed
     */
    public function getId()
    {
        return $this->id;
    }


    /**
     * Gets expiration date in unix timestamp
     *
     * @return int
     */
    public function getExpiresAt()
    {
        return $this->expiresAt;
    }

    /**
     * Gets redirect uri associated with this code
     *
     * @return string|null
     */
    public function getRedirectUri()
    {
        return $this->redirectUri;
    }

    /**
     * Gets scopes associated with this code
     *
     * @return IScope[]
     */
    public function getScopes()
    {
        return $this->scopes;
    }

    /**
     * Gets user associated with this code
     *
     * @return IUser
     */
    public function getUser()
    {
        return $this->user;
    }

    /**
     * Gets client associated with this code
     *
     * @return IClient
     */
    public function getClient()
    {
        return $this->client;
    }

    /**
     * Gets state if was provided
     *
     * @return string|null
     */
    public function getState()
    {
        return $this->state;
    }
}
 