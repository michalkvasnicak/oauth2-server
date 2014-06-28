<?php

namespace OAuth2\Security;

use OAuth2\GrantType\IAuthorizationGrantType;
use OAuth2\Resolver\IGrantTypeResolver;
use OAuth2\Http\IRequest;
use OAuth2\Exception\UnsupportedResponseTypeException;
use OAuth2\Storage\IUser;

/**
 * @author Michal Kvasničák <michal.kvasnicak@mink.sk>
 */
class Authorizator
{

    /** @var IGrantTypeResolver */
    protected $grantTypeResolver;


    public function __construct(IGrantTypeResolver $grantTypeResolver)
    {
        $this->grantTypeResolver = $grantTypeResolver;
    }


    /**
     * Authorizes request using grant type with authorization
     *
     * @param IRequest $request
     * @param IUser $user   logged user
     *
     * @return IAuthorizationSession
     * @throws \OAuth2\Exception\UnsupportedResponseTypeException
     */
    public function authorize(IRequest $request, IUser $user)
    {
        // resolve grant type for current request
        $grantType = $this->grantTypeResolver->resolve($request);

        if (!$grantType instanceof IAuthorizationGrantType) {
            throw new UnsupportedResponseTypeException;
        }

        return $grantType->authorize($request, $user);
    }

}
