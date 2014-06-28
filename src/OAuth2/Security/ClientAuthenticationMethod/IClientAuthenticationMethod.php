<?php

namespace OAuth2\Security\ClientAuthenticationMethod;

use OAuth2\Exception\InvalidClientException;
use OAuth2\Http\IRequest;
use OAuth2\Storage\IClient;

/**
 * @author Michal Kvasničák <michal.kvasnicak@mink.sk>
 */
interface IClientAuthenticationMethod
{

    /**
     * Matches if client authentication method can be used for given request
     *
     * @param IRequest $request
     *
     * @return bool
     */
    public function match(IRequest $request);


    /**
     * Authenticates client and returns it
     *
     * @param IRequest $request
     *
     * @return IClient
     * @throws InvalidClientException
     */
    public function authenticate(IRequest $request);

}
