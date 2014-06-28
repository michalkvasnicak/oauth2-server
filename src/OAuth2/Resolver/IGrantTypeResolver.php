<?php

namespace OAuth2\Resolver;

use OAuth2\GrantType\IAuthorizationGrantType;
use OAuth2\GrantType\IGrantType;
use OAuth2\Http\IRequest;

/**
 * @author Michal Kvasničák <michal.kvasnicak@mink.sk>
 */
interface IGrantTypeResolver 
{

    /**
     * Resolves grant type for given request
     *
     * @param IRequest $request
     *
     * @return IGrantType|IAuthorizationGrantType
     * @throws \OAuth2\Exception\UnsupportedGrantTypeException
     */
    public function resolve(IRequest $request);

}
