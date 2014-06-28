<?php

namespace OAuth2\GrantType;

use OAuth2\Exception\InvalidGrantException;
use OAuth2\Exception\InvalidRequestException;
use OAuth2\Exception\UnauthorizedClientException;
use OAuth2\Resolver\IScopeResolver;
use OAuth2\Security\IClientAuthenticator;
use OAuth2\Storage\IAccessToken;
use OAuth2\Http\IRequest;
use OAuth2\Security\AuthorizationCodeSession;
use OAuth2\Storage\IAccessTokenStorage;
use OAuth2\Storage\IAuthorizationCodeStorage;
use OAuth2\Storage\IClientStorage;
use OAuth2\Storage\IUser;

/**
 * @author Michal Kvasničák <michal.kvasnicak@mink.sk>
 */
class AuthorizationCode extends AAuthorizationGrantType
{

    /**
     * @var \OAuth2\Security\IClientAuthenticator
     */
    private $clientAuthenticator;

    /**
     * @var \OAuth2\Storage\IAuthorizationCodeStorage
     */
    private $authorizationCodeStorage;

    /**
     * @var \OAuth2\Storage\IAccessTokenStorage
     */
    private $accessTokenStorage;


    public function __construct(
        IClientAuthenticator $clientAuthenticator,
        IClientStorage $clientStorage,
        IAuthorizationCodeStorage $authorizationCodeStorage,
        IAccessTokenStorage $accessTokenStorage,
        IScopeResolver $scopeResolver
    ) {
        parent::__construct($clientStorage, $scopeResolver);

        $this->clientAuthenticator = $clientAuthenticator;
        $this->authorizationCodeStorage = $authorizationCodeStorage;
        $this->accessTokenStorage = $accessTokenStorage;
    }


    /**
     * Authorizes request
     *
     * @param IRequest $request
     * @param IUser $user   logged user
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

        // redirect uri is without authorization code!
        $authorizationCode = $this->authorizationCodeStorage->generate(
            $user,
            $requirements['client'],
            $requirements['scopes'],
            $requirements['redirect_uri'],
            $requirements['state']
        );

        return new AuthorizationCodeSession(
            $authorizationCode
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
            return $request->query('response_type') === 'code';
        } else {
            return $request->request('grant_type') === 'authorization_code';
        }
    }

    /**
     * Grants access token for request
     *
     * @param IRequest $request
     *
     * @throws \OAuth2\Exception\InvalidGrantException
     * @throws \OAuth2\Exception\InvalidRequestException
     * @throws \OAuth2\Exception\UnauthorizedClientException
     * @return IAccessToken
     */
    public function grant(IRequest $request)
    {
        $code = $request->request('code');

        if (empty($code)) {
            throw new InvalidRequestException("Parameter 'code' is missing.");
        }

        $client = $this->clientAuthenticator->authenticate($request);

        if (!$client->isAllowedToUse($this)) {
            throw new UnauthorizedClientException('Client can not use this grant type.');
        }

        $authorizationCode = $this->authorizationCodeStorage->get($code);

        if (!$authorizationCode) {
            throw new InvalidGrantException('Authorization code is invalid.');
        }

        if ($authorizationCode->getExpiresAt() < time()) {
            throw new InvalidGrantException('Authorization code has expired.');
        }

        if ($client->getId() !== $authorizationCode->getClient()->getId()) {
            throw new InvalidGrantException('Authorization code is invalid.');
        }

        $redirectUri = $request->request('redirect_uri');
        $codeRedirectUri = $authorizationCode->getRedirectUri();

        if (!empty($redirectUri)) {
            if (empty($codeRedirectUri) || $redirectUri !== $codeRedirectUri) {
                throw new InvalidRequestException(
                    'Redirect URI is missing, was not used in authorization or is invalid.'
                );
            }
        } else {
            if (!empty($codeRedirectUri)) {
                throw new InvalidRequestException(
                    'Redirect URI is missing, was not used in authorization or is invalid.'
                );
            }
        }

        return $this->accessTokenStorage->generate(
            $authorizationCode->getUser(),
            $authorizationCode->getClient(),
            $authorizationCode->getScopes()
        );
    }

}
