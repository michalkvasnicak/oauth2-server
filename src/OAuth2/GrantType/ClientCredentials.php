<?php

namespace OAuth2\GrantType;

use OAuth2\Exception\InvalidClientException;
use OAuth2\Exception\InvalidScopeException;
use OAuth2\Exception\UnauthorizedClientException;
use OAuth2\Resolver\IScopeResolver;
use OAuth2\Security\IClientAuthenticator;
use OAuth2\Storage\IAccessToken;
use OAuth2\Http\IRequest;
use OAuth2\Storage\IAccessTokenStorage;

/**
 * @author Michal Kvasničák <michal.kvasnicak@mink.sk>
 */
class ClientCredentials implements IGrantType
{


    /**
     * @var \OAuth2\Security\IClientAuthenticator
     */
    private $clientAuthenticator;

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
        IAccessTokenStorage $accessTokenStorage,
        IScopeResolver $scopeResolver
    ) {
        $this->clientAuthenticator = $clientAuthenticator;
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
        return $request->request('grant_type') === 'client_credentials';
    }

    /**
     * Grants access token for request
     *
     * @param IRequest $request
     *
     * @throws \OAuth2\Exception\InvalidClientException
     * @throws \OAuth2\Exception\InvalidScopeException
     * @return IAccessToken
     */
    public function grant(IRequest $request)
    {
        $client = $this->clientAuthenticator->authenticate($request);

        if (!$client->isAllowedToUse($this)) {
            throw new UnauthorizedClientException('Client can not use this grant type.');
        }

        if (empty($client->getSecret())) {
            throw new InvalidClientException('Only confidential clients can use this method.');
        }

        $requestedScopes = $request->request('scope');
        $availableScopes = $client->getScopes();

        if (empty($availableScopes)) {
            $availableScopes = $this->scopeResolver->getDefaultScopes();
        }

        if (empty($availableScopes)) {
            throw new InvalidScopeException('Scope parameter has to be specified.');
        }

        $scopes = $this->scopeResolver->intersect($requestedScopes, $availableScopes);

        return $this->accessTokenStorage->generate(
            $client->getOwner(),
            $client,
            $scopes
        );
    }

}
