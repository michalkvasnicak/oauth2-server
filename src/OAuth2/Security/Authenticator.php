<?php

namespace OAuth2\Security;

use OAuth2\Http\IRequest;
use OAuth2\Exception\NotAuthenticatedException;
use OAuth2\Storage\IAccessTokenStorage;
use OAuth2\Resolver\ITokenTypeResolver;

/**
 * @author Michal Kvasničák <michal.kvasnicak@mink.sk>
 */
class Authenticator
{

    /**
     * @var \OAuth2\Resolver\ITokenTypeResolver
     */
    protected $tokenTypeResolver;

    /**
     * @var \OAuth2\Storage\IAccessTokenStorage
     */
    protected $accessTokenStorage;


    public function __construct(ITokenTypeResolver $tokenTypeResolver, IAccessTokenStorage $accessTokenStorage)
    {
        $this->tokenTypeResolver = $tokenTypeResolver;
        $this->accessTokenStorage = $accessTokenStorage;
    }


    /**
     * Authenticates current request and returns session
     *
     * @param IRequest $request
     *
     * @throws \OAuth2\Exception\NotAuthenticatedException
     * @return Session
     */
    public function authenticate(IRequest $request)
    {
        // resolve token type from request
        $tokenType = $this->tokenTypeResolver->resolve($request);

        $accessToken = $this->accessTokenStorage->get($tokenType->getAccessToken());

        if (!$accessToken) {
            throw new NotAuthenticatedException;
        }

        return new Session($accessToken);
    }

}
