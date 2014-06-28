<?php

namespace tests\OAuth2\Fixtures;

use OAuth2\GrantType\IGrantType;
use OAuth2\Storage\IClient;
use OAuth2\Storage\IScope;
use OAuth2\Storage\IUser;

/**
 * @author Michal Kvasničák <michal.kvasnicak@mink.sk>
 */
class Client implements IClient
{

    /**
     * @var
     */
    private $id;

    /**
     * @var null
     */
    private $secret;

    /**
     * @var array
     */
    private $grantTypes;

    /**
     * @var array
     */
    private $scopes = [];

    /**
     * @var \OAuth2\Storage\IUser
     */
    private $owner;

    /**
     * @var
     */
    private $redirectUri;


    public function __construct(
        $id,
        $secret = null,
        array $grantTypes = [],
        array $scopes = [],
        IUser $owner = null,
        $redirectUri = null
    ) {
        $this->id = $id;
        $this->secret = $secret;
        $this->grantTypes = $grantTypes;
        $this->scopes = $scopes;
        $this->owner = $owner;
        $this->redirectUri = $redirectUri;
    }


    /**
     * Gets client identifier
     *
     * @return mixed
     */
    public function getId()
    {
        return $this->id;
    }

    /**
     * Gets client secret key (if is confidential)
     *
     * @return string|null
     */
    public function getSecret()
    {
        return $this->secret;
    }

    /**
     * Is client allowed to use grant type?
     *
     * @param IGrantType $grantType
     *
     * @return bool
     */
    public function isAllowedToUse(IGrantType $grantType)
    {
        foreach ($this->grantTypes as $gt) {
            if ($gt === $grantType) {
                return true;
            }
        }

        return false;
    }

    /**
     * Gets scopes associated with client (which is allowed to access)
     *
     * @return IScope[]
     */
    public function getScopes()
    {
        return $this->scopes;
    }

    /**
     * Gets client owner (creator) if exists
     *
     * @return IUser|null
     */
    public function getOwner()
    {
        return $this->owner;
    }

    /**
     * Gets client redirect uri
     *
     * @return string|null
     */
    public function getRedirectUri()
    {
        return $this->redirectUri;
    }
}
 