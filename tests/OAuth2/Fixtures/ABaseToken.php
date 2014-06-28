<?php

namespace tests\OAuth2\Fixtures;

use OAuth2\Storage\IClient;
use OAuth2\Storage\IScope;
use OAuth2\Storage\IToken;
use OAuth2\Storage\IUser;

/**
 * @author Michal Kvasničák <michal.kvasnicak@mink.sk>
 */
abstract class ABaseToken implements IToken
{

    public $id;

    /**
     * @var \OAuth2\Storage\IUser
     */
    private $user;

    /**
     * @var \OAuth2\Storage\IClient
     */
    private $client;

    /**
     * @var IScope[]
     */
    private $scopes;

    /**
     * @var int
     */
    private $expiresAt;

    public function __construct($id, IUser $user = null, IClient $client, array $scopes = [], $expiresAt)
    {
        $this->user = $user;
        $this->client = $client;
        $this->scopes = $scopes;
        $this->expiresAt = $expiresAt;
        $this->id = $id;
    }


    public function getId()
    {
        return $this->id;
    }


    /**
     * Gets user associated with this access token
     *
     * @return IUser
     */
    public function getUser()
    {
        return $this->user;
    }

    /**
     * Gets client associated with this access token
     *
     * @return IClient
     */
    public function getClient()
    {
        return $this->client;
    }

    /**
     * Gets associated scopes
     *
     * @return IScope[]
     */
    public function getScopes()
    {
        return $this->scopes;
    }

    /**
     * Has access token associated scope?
     *
     * @param mixed $scope
     *
     * @return bool
     */
    public function hasScope($scope)
    {
        foreach ($this->scopes as $s) {
            if ($s->getId() === $scope) {
                return true;
            }
        }

        return false;
    }

    /**
     * Gets expiration time (timestamp)
     *
     * @return int
     */
    public function getExpiresAt()
    {
        return $this->expiresAt;
    }
}
 