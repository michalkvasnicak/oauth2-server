<?php

namespace OAuth2\Security\ClientAuthenticationMethod;

use OAuth2\Exception\InvalidClientException;
use OAuth2\Storage\IClient;
use OAuth2\Http\IRequest;
use OAuth2\Storage\IClientStorage;

/**
 * @author Michal Kvasničák <michal.kvasnicak@mink.sk>
 */
class HttpBasic implements IClientAuthenticationMethod
{

    /**
     * @var \OAuth2\Storage\IClientStorage
     */
    private $clientStorage;


    public function __construct(IClientStorage $clientStorage)
    {
        $this->clientStorage = $clientStorage;
    }


    /**
     * Matches if client authentication method can be used for given request
     *
     * @param IRequest $request
     *
     * @return bool
     */
    public function match(IRequest $request)
    {
        return strpos($request->headers('authorization', ''), 'Basic') === 0;
    }

    /**
     * Authenticates client and returns it
     *
     * @param IRequest $request
     *
     * @return IClient
     * @throws InvalidClientException
     */
    public function authenticate(IRequest $request)
    {
        $id = $request->headers('PHP_AUTH_USER');
        $secret = $request->headers('PHP_AUTH_PW');

        if (!$id) {
            throw new InvalidClientException('Client id is missing.');
        }

        // find client or throw exception if does not exist
        if (!$client = $this->clientStorage->get($id)) {
            throw new InvalidClientException('Invalid client credentials.');
        }

        // if client is confidential and secrets does not match
        // or if client is public (does not have secret key) and credentials contains secret
        // throw exception
        if ((string) $secret !== (string) $client->getSecret()) {
            throw new InvalidClientException('Invalid client credentials.');
        }

        return $client;
    }

}
