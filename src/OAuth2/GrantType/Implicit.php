<?php

namespace OAuth2\GrantType;

use OAuth2\Http\IRequest;
use OAuth2\Resolver\IScopeResolver;
use OAuth2\Security\AuthorizationCodeSession;
use OAuth2\Security\ImplicitSession;
use OAuth2\Storage\IAccessToken;
use OAuth2\Storage\IAccessTokenStorage;
use OAuth2\Storage\IClientStorage;
use OAuth2\Storage\IUser;
use OAuth2\TokenType\ITokenType;

/**
 * @author Michal Kvasničák <michal.kvasnicak@mink.sk>
 */
class Implicit extends AAuthorizationGrantType
{

    /**
     * @var \OAuth2\Storage\IAccessTokenStorage
     */
    private $accessTokenStorage;

    /**
     * @var \OAuth2\TokenType\ITokenType
     */
    private $tokenType;


    public function __construct(
        IClientStorage $clientStorage,
        IAccessTokenStorage $accessTokenStorage,
        IScopeResolver $scopeResolver,
        ITokenType $tokenType
    ) {
        parent::__construct($clientStorage, $scopeResolver);

        $this->accessTokenStorage = $accessTokenStorage;
        $this->tokenType = $tokenType;
    }

    /**
     * Authorizes request
     *
     * @param IRequest $request
     * @param IUser $user logged user
     *
     * @throws \OAuth2\Exception\InvalidClientException
     * @throws \OAuth2\Exception\InvalidRequestException
     * @throws \OAuth2\Exception\InvalidScopeException
     * @throws \OAuth2\Exception\UnauthorizedClientException
     * @return AuthorizationCodeSession
     */
    public function authorize(IRequest $request, IUser $user)
    {
        $requirements = parent::parseAuthorizationRequest($request);

        $accessToken = $this->accessTokenStorage->generate(
            $user,
            $requirements['client'],
            $requirements['scopes']
        );

        return new ImplicitSession(
            $accessToken,
            $this->tokenType->getName(),
            $requirements['redirect_uri'],
            $requirements['state']
        );
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
        if ($request->isMethod('GET')) {
            return $request->query('response_type') === 'token';
        }

        return false;
    }

    /**
     * Grants access token for request
     *
     * @param IRequest $request
     *
     * @return IAccessToken
     */
    public function grant(IRequest $request)
    {
        throw new \RuntimeException('Implicit grant type can not be used in token endpoint.');
    }

}
 