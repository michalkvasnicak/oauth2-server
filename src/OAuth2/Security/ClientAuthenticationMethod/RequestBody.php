<?php

namespace OAuth2\Security\ClientAuthenticationMethod;

use OAuth2\Exception\InvalidClientException;
use OAuth2\Http\IRequest;
use OAuth2\Storage\IClient;
use OAuth2\Storage\IClientStorage;

/**
 * @author Michal Kvasničák <michal.kvasnicak@mink.sk>
 */
class RequestBody implements IClientAuthenticationMethod
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
        return $request->headers('authorization') === null;
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
        $id = $request->request('client_id');
        $secret = $request->request('client_secret');

        if (!$id) {
            throw new InvalidClientException('Client id is missing.');
        }

        if (!$client = $this->clientStorage->get($id)) {
            throw new InvalidClientException('Invalid client credentials.');
        }

        if ((string) $secret !== (string) $client->getSecret()) {
            throw new InvalidClientException('Invalid client credentials.');
        }

        return $client;
    }

}
