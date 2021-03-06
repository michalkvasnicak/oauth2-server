<?php

namespace OAuth2\GrantType;

use OAuth2\Exception\InvalidGrantException;
use OAuth2\Exception\InvalidRequestException;
use OAuth2\Exception\InvalidScopeException;
use OAuth2\Exception\InvalidUserCredentialsException;
use OAuth2\Exception\UnauthorizedClientException;
use OAuth2\Resolver\IScopeResolver;
use OAuth2\Security\IClientAuthenticator;
use OAuth2\Security\IUserAuthenticator;
use OAuth2\Storage\IAccessToken;
use OAuth2\Http\IRequest;
use OAuth2\Storage\IAccessTokenStorage;

/**
 * @author Michal Kvasničák <michal.kvasnicak@mink.sk>
 */
class ResourceOwnerPasswordCredentials implements IGrantType
{


    /**
     * @var \OAuth2\Security\IClientAuthenticator
     */
    private $clientAuthenticator;

    /**
     * @var \OAuth2\Security\IUserAuthenticator
     */
    private $userAuthenticator;

    /**
     * @var \OAuth2\Storage\IAccessTokenStorage
     */
    private $accessTokenStorage;

    /**
     * @var \OAuth2\Resolver\IScopeResolver
     */
    private $scopeResolver;


    public function __construct(
        IClientAuthenticator $clientAuthenticator,
        IUserAuthenticator $userAuthenticator,
        IAccessTokenStorage $accessTokenStorage,
        IScopeResolver $scopeResolver
    ) {
        $this->clientAuthenticator = $clientAuthenticator;
        $this->userAuthenticator = $userAuthenticator;
        $this->accessTokenStorage = $accessTokenStorage;
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
        return $request->request('grant_type') === 'password';
    }

    /**
     * Grants access token for request
     *
     * @param IRequest $request
     *
     * @throws \OAuth2\Exception\InvalidGrantException
     * @throws \OAuth2\Exception\InvalidRequestException
     * @throws \OAuth2\Exception\InvalidScopeException
     * @throws \OAuth2\Exception\UnauthorizedClientException
     * @return IAccessToken
     */
    public function grant(IRequest $request)
    {
        $username = $request->request('username');
        $password = $request->request('password');

        if (empty($username) || empty($password)) {
            throw new InvalidRequestException('Username and password are required.');
        }

        $client = $this->clientAuthenticator->authenticate($request);

        if (!$client->isAllowedToUse($this)) {
            throw new UnauthorizedClientException('Client can not use this grant type.');
        }

        $user = $this->userAuthenticator->authenticate($username, $password);

        if (!$user) {
            throw new InvalidUserCredentialsException('Invalid user credentials.');
        }

        $requestedScopes = $request->request('scope');
        $availableScopes = $user->getScopes();

        if (empty($availableScopes)) {
            $availableScopes = $this->scopeResolver->getDefaultScopes();
        }

        if (empty($availableScopes)) {
            throw new InvalidScopeException('Scope parameter has to be specified.');
        }

        // intersection of requested and user scopes
        $scopes = $this->scopeResolver->intersect($requestedScopes, $availableScopes);

        return $this->accessTokenStorage->generate(
            $user,
            $client,
            $scopes
        );
    }

}
