<?php

namespace OAuth2\GrantType;

use OAuth2\Exception\InvalidGrantException;
use OAuth2\Exception\MissingParameterException;
use OAuth2\Exception\UnauthorizedClientException;
use OAuth2\Resolver\IScopeResolver;
use OAuth2\Security\IClientAuthenticator;
use OAuth2\Storage\IAccessToken;
use OAuth2\Http\IRequest;
use OAuth2\Storage\IAccessTokenStorage;
use OAuth2\Storage\IRefreshTokenStorage;

/**
 * @author Michal Kvasničák <michal.kvasnicak@mink.sk>
 */
class RefreshToken implements IGrantType
{

    /**
     * @var \OAuth2\Storage\IRefreshTokenStorage
     */
    protected $refreshTokenStorage;

    /**
     * @var \OAuth2\Storage\IAccessTokenStorage
     */
    protected $accessTokenStorage;

    /**
     * @var \OAuth2\Security\IClientAuthenticator
     */
    private $clientAuthenticator;

    /**
     * @var \OAuth2\Resolver\IScopeResolver
     */
    private $scopeResolver;


    public function __construct(
        IClientAuthenticator $clientAuthenticator,
        IRefreshTokenStorage $refreshTokenStorage,
        IAccessTokenStorage $accessTokenStorage,
        IScopeResolver $scopeResolver
    ) {
        $this->refreshTokenStorage = $refreshTokenStorage;
        $this->accessTokenStorage = $accessTokenStorage;
        $this->clientAuthenticator = $clientAuthenticator;
        $this->scopeResolver = $scopeResolver;
    }


    /**
     * Does grant type match given request?
     *
     * @param IRequest $request
     *
     * @return bool
     */
    public function match(IRequest $request)
    {
        return $request->request('grant_type') === 'refresh_token';
    }

    /**
     * Grants access token for request
     *
     * @param IRequest $request
     *
     * @throws \OAuth2\Exception\InvalidGrantException
     * @throws \OAuth2\Exception\MissingParameterException
     * @throws \OAuth2\Exception\UnauthorizedClientException
     * @return IAccessToken
     */
    public function grant(IRequest $request)
    {
        if (!$refreshTokenIdentifier = $request->request('refresh_token')) {
            throw new MissingParameterException("Parameter 'refresh_token' is missing.");
        }

        if (!$refreshToken = $this->refreshTokenStorage->get($refreshTokenIdentifier)) {
            throw new InvalidGrantException('Invalid refresh token.');
        }

        $client = $this->clientAuthenticator->authenticate($request);

        // are clients same?
        if ($client->getId() !== $refreshToken->getClient()->getId()) {
            throw new InvalidGrantException('Invalid refresh token.');
        }

        // is client allowed to use this grant type?
        if (!$client->isAllowedToUse($this)) {
            throw new UnauthorizedClientException('Client can not use this grant type.');
        }

        $expiresAt = $refreshToken->getExpiresAt();

        if ($expiresAt instanceof \DateTime) {
            $expiresAt = $expiresAt->getTimestamp();
        }

        // is refresh token expired?
        if ($refreshToken->getExpiresAt() < time()) {
            throw new InvalidGrantException('Refresh token has expired.');
        }

        // intersection of refresh token and requested scopes
        $scopes = $this->scopeResolver->intersect($request->request('scope'), $refreshToken->getScopes());

        return $this->accessTokenStorage->generate(
            $refreshToken->getUser(),
            $refreshToken->getClient(),
            $scopes
        );
    }

}
