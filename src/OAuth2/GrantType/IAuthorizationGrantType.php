<?php

namespace OAuth2\GrantType;

use OAuth2\Http\IRequest;
use OAuth2\Security\IAuthorizationSession;
use OAuth2\Storage\IUser;

/**
 * @author Michal Kvasničák <michal.kvasnicak@mink.sk>
 */
interface IAuthorizationGrantType extends IGrantType
{

    /**
     * Authorizes request
     *
     * @param IRequest $request
     * @param IUser $user   logged user
     *
     * @return IAuthorizationSession
     */
    public function authorize(IRequest $request, IUser $user);

}
