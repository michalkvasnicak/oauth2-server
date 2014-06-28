<?php

namespace OAuth2\Resolver;

use OAuth2\Exception\UnsupportedGrantTypeException;
use OAuth2\GrantType\IAuthorizationGrantType;
use OAuth2\GrantType\IGrantType;
use OAuth2\Http\IRequest;

/**
 * @author Michal Kvasničák <michal.kvasnicak@mink.sk>
 */
class GrantTypeResolver implements IGrantTypeResolver
{

    /** @var IGrantType[] */
    protected $grantTypes = [];


    /**
     * Adds accepted grant type
     *
     * @param IGrantType $grantType
     */
    public function accept(IGrantType $grantType)
    {
        $this->grantTypes[] = $grantType;
    }


    /**
     * Resolves grant type for given request
     *
     * @param IRequest $request
     *
     * @return IGrantType|IAuthorizationGrantType
     * @throws \OAuth2\Exception\UnsupportedGrantTypeException
     */
    public function resolve(IRequest $request)
    {
        foreach ($this->grantTypes as $grantType) {
            if ($grantType->match($request)) {
                return $grantType;
            }
        }

        throw new UnsupportedGrantTypeException;
    }

}
