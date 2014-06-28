<?php

namespace OAuth2\Security;

use OAuth2\Exception\InvalidClientException;
use OAuth2\Security\ClientAuthenticationMethod\IClientAuthenticationMethod;
use OAuth2\Storage\IClient;
use OAuth2\Http\IRequest;

/**
 * @author Michal Kvasničák <michal.kvasnicak@mink.sk>
 */
class ClientAuthenticator implements IClientAuthenticator
{

    /**
     * @var IClientAuthenticationMethod[]
     */
    protected $clientAuthenticationMethods = [];


    /**
     * Accepts given client authentication method
     *
     * @param \OAuth2\Security\ClientAuthenticationMethod\IClientAuthenticationMethod $clientAuthenticatorMethod
     */
    public function accept(IClientAuthenticationMethod $clientAuthenticatorMethod)
    {
        $this->clientAuthenticationMethods[] = $clientAuthenticatorMethod;
    }


    /**
     * Authenticates client using credentials from request
     *
     * @param IRequest $request
     *
     * @return IClient
     * @throws InvalidClientException
     */
    public function authenticate(IRequest $request)
    {
        foreach ($this->clientAuthenticationMethods as $clientAuthenticationMethod) {
            if ($clientAuthenticationMethod->match($request)) {
                return $clientAuthenticationMethod->authenticate($request);
            }
        }

        throw new InvalidClientException('Invalid client authentication method.');
    }

}
