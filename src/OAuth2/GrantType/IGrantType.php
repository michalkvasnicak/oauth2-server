<?php

namespace OAuth2\GrantType;

use OAuth2\Http\IRequest;
use OAuth2\Storage\IAccessToken;

/**
 * @author Michal Kvasničák <michal.kvasnicak@mink.sk>
 */
interface IGrantType 
{


    /**
     * Does grant type match given request?
     *
     * @param IRequest $request
     *
     * @return bool
     */
    public function match(IRequest $request);


    /**
     * Grants access token for request
     *
     * @param IRequest $request
     *
     * @return IAccessToken
     */
    public function grant(IRequest $request);

}
 