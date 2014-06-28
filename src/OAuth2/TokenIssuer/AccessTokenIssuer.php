<?php

namespace OAuth2\TokenIssuer;

use OAuth2\Exception\InvalidHttpMethodException;
use OAuth2\Resolver\IGrantTypeResolver;
use OAuth2\Http\IRequest;

/**
 * @author Michal Kvasničák <michal.kvasnicak@mink.sk>
 */
class AccessTokenIssuer 
{

    /** @var \OAuth2\Resolver\IGrantTypeResolver  */
    protected $grantTypeResolver;


    public function __construct(IGrantTypeResolver $grantTypeResolver)
    {
        $this->grantTypeResolver = $grantTypeResolver;
    }


    /**
     * Issues access token using grant type from current request
     *
     * @param IRequest $request
     *
     * @return \OAuth2\Storage\IAccessToken
     * @throws \OAuth2\Exception\InvalidHttpMethodException
     */
    public function issueToken(IRequest $request)
    {
        if (!$request->isMethod('post')) {
            throw new InvalidHttpMethodException;
        }

        $grantType = $this->grantTypeResolver->resolve($request);

        return $grantType->grant($request);
    }

}
