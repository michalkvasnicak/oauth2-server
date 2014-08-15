<?php

namespace tests;

use OAuth2\Resolver\GrantTypeResolver;
use OAuth2\Resolver\ScopeResolver;
use OAuth2\Security\Authorizator;
use OAuth2\Security\ClientAuthenticationMethod\HttpBasic;
use OAuth2\Security\ClientAuthenticationMethod\RequestBody;
use OAuth2\Security\ClientAuthenticator;
use OAuth2\TokenIssuer\AccessTokenIssuer;
use tests\OAuth2\Fixtures\MemoryAccessTokenStorage;
use tests\OAuth2\Fixtures\MemoryAuthorizationCodeStorage;
use tests\OAuth2\Fixtures\MemoryClientStorage;
use tests\OAuth2\Fixtures\MemoryRefreshTokenStorage;
use tests\OAuth2\Fixtures\MemoryUserAuthenticator;

/**
 * @author Michal Kvasničák <michal.kvasnicak@mink.sk>
 */
class OAuth2GrantTypeTestCase extends \PHPUnit_Framework_TestCase
{

    /** @var ScopeResolver  */
    private $scopeResolver;

    /** @var MemoryAccessTokenStorage  */
    private $accessTokenStorage;

    /** @var  GrantTypeResolver  */
    private $grantTypeResolver;

    /** @var  AccessTokenIssuer */
    private $accessTokenIssuer;

    /** @var  ClientAuthenticator */
    private $clientAuthenticator;

    /** @var  MemoryClientStorage */
    private $clientStorage;

    /** @var  MemoryAuthorizationCodeStorage */
    private $authorizationCodeStorage;

    /** @var  Authorizator */
    private $authorizator;

    /** @var MemoryRefreshTokenStorage */
    private $refreshTokenStorage;

    /** @var  MemoryUserAuthenticator */
    private $userAuthenticator;

    /**
     * @return AccessTokenIssuer
     */
    public function getAccessTokenIssuer()
    {
        return $this->accessTokenIssuer;
    }

    /**
     * @return MemoryAccessTokenStorage
     */
    public function getAccessTokenStorage()
    {
        return $this->accessTokenStorage;
    }

    /**
     * @return ClientAuthenticator
     */
    public function getClientAuthenticator()
    {
        return $this->clientAuthenticator;
    }

    /**
     * @return MemoryClientStorage
     */
    public function getClientStorage()
    {
        return $this->clientStorage;
    }

    /**
     * @return GrantTypeResolver
     */
    public function getGrantTypeResolver()
    {
        return $this->grantTypeResolver;
    }

    /**
     * @return ScopeResolver
     */
    public function getScopeResolver()
    {
        return $this->scopeResolver;
    }

    /**
     * @return MemoryAuthorizationCodeStorage
     */
    public function getAuthorizationCodeStorage()
    {
        return $this->authorizationCodeStorage;
    }

    /**
     * @return Authorizator
     */
    public function getAuthorizator()
    {
        return $this->authorizator;
    }

    /**
     * @return MemoryRefreshTokenStorage
     */
    public function getRefreshTokenStorage()
    {
        return $this->refreshTokenStorage;
    }

    /**
     * @return MemoryUserAuthenticator
     */
    public function getUserAuthenticator()
    {
        return $this->userAuthenticator;
    }


    protected function setUp()
    {
        parent::setUp();

        $this->scopeResolver = new ScopeResolver();
        $this->accessTokenStorage = new MemoryAccessTokenStorage();
        $this->grantTypeResolver = new GrantTypeResolver();
        $this->clientStorage = new MemoryClientStorage();
        $this->clientAuthenticator = new ClientAuthenticator();
        $this->accessTokenIssuer = new AccessTokenIssuer($this->grantTypeResolver);
        $this->authorizationCodeStorage = new MemoryAuthorizationCodeStorage();
        $this->refreshTokenStorage = new MemoryRefreshTokenStorage();
        $this->userAuthenticator = new MemoryUserAuthenticator();

        $this->clientAuthenticator->accept(new HttpBasic($this->clientStorage));
        $this->clientAuthenticator->accept(new RequestBody($this->clientStorage));

        $this->authorizator = new Authorizator($this->grantTypeResolver);
    }

}
 