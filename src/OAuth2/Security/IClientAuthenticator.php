<?php

namespace OAuth2\Security;

use OAuth2\Exception\InvalidClientException;
use OAuth2\Http\IRequest;
use OAuth2\Storage\IClient;

/**
 * @author Michal Kvasničák <michal.kvasnicak@mink.sk>
 */
interface IClientAuthenticator 
{

    /**
     * Authenticates client using credentials from request
     *
     * @param IRequest $request
     *
     * @return IClient
     * @throws InvalidClientException
     */
    public function authenticate(IRequest $request);

}
