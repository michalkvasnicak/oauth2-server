<?php

namespace OAuth2\GrantType;

use OAuth2\Exception\InvalidClientException;
use OAuth2\Exception\InvalidRequestException;
use OAuth2\Exception\InvalidScopeException;
use OAuth2\Exception\UnauthorizedClientException;
use OAuth2\Http\IRequest;
use OAuth2\Resolver\IScopeResolver;
use OAuth2\Storage\IClientStorage;

/**
 * @author Michal Kvasničák <michal.kvasnicak@mink.sk>
 */
abstract class AAuthorizationGrantType implements IAuthorizationGrantType
{

    /**
     * @var IClientStorage
     */
    private $clientStorage;

    /**
     * @var IScopeResolver
     */
    private $scopeResolver;


    public function __construct(IClientStorage $clientStorage, IScopeResolver $scopeResolver)
    {
        $this->clientStorage = $clientStorage;
        $this->scopeResolver = $scopeResolver;
    }


    /**
     * Parses authorization request
     *
     * @param IRequest $request
     *
     * @return array
     *
     * @throws \OAuth2\Exception\InvalidClientException
     * @throws \OAuth2\Exception\InvalidRequestException
     * @throws \OAuth2\Exception\InvalidScopeException
     * @throws \OAuth2\Exception\UnauthorizedClientException
     */
    protected function parseAuthorizationRequest(IRequest $request)
    {
        $clientId = $request->query('client_id');

        if (!$clientId) {
            throw new InvalidRequestException('Client id is missing.');
        }

        $client = $this->clientStorage->get($clientId);

        if (!$client) {
            throw new InvalidClientException('Invalid client.');
        }

        if (!$client->isAllowedToUse($this)) {
            throw new UnauthorizedClientException('Client can not use this grant type.');
        }

        $redirectUri = $request->query('redirect_uri');
        $clientRedirectUri = $client->getRedirectUri();

        if ($redirectUri) {
            $parsedUrl = parse_url($redirectUri);

            if ($parsedUrl === false || isset($parsedUrl['fragment'])) {
                throw new InvalidRequestException('Redirect URI is invalid.');
            }

            if (!$this->compareUris($redirectUri, $clientRedirectUri)) {
                throw new InvalidRequestException('Redirect URI does not match.');
            }
        } else {
            // use registered redirect uri or throw exception

            if (!$clientRedirectUri) {
                throw new InvalidRequestException('Redirect URI was not supplied or registered.');
            }

            $redirectUri = $clientRedirectUri;
        }

        $requestedScopes = $request->query('scope');
        $availableScopes = $client->getScopes();

        if (!$availableScopes) {
            $availableScopes = $this->scopeResolver->getDefaultScopes();
        }

        if (empty($availableScopes)) {
            throw new InvalidScopeException('Scope parameter has to be specified.');
        }

        $scopes = $this->scopeResolver->intersect($requestedScopes, $availableScopes);

        return [
            'client' => $client,
            'redirect_uri' => $redirectUri,
            'state' => $request->query('state'),
            'scopes' => $scopes
        ];
    }


    /**
     * Compares uris and returns true if uris matches (case sensitive)
     *
     * @param string $redirect_uri
     * @param string $clientRedirectUri
     *
     * @return bool
     */
    private function compareUris($redirect_uri, $clientRedirectUri)
    {
        if (!$redirect_uri || !$clientRedirectUri) {
            return false;
        }

        $wanted = array_fill_keys(['scheme', 'host', 'port', 'path'], true);

        // gets only scheme, host, port, path from uri
        $redirect_uri = array_intersect_key(parse_url($redirect_uri), $wanted);
        $clientRedirectUri = array_intersect_key(parse_url($clientRedirectUri), $wanted);

        return strcmp(implode($redirect_uri), implode($clientRedirectUri)) === 0;
    }

}
