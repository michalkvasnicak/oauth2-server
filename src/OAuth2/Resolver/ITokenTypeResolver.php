<?php

namespace OAuth2\Resolver;

use OAuth2\Http\IRequest;
use OAuth2\TokenType\ITokenType;

/**
 * @author Michal Kvasničák <michal.kvasnicak@mink.sk>
 */
interface ITokenTypeResolver 
{

    /**
     * Adds accepted token type
     *
     * @param ITokenType $tokenType
     */
    public function accept(ITokenType $tokenType);


    /**
     * Resolves token type from request
     *
     * @param IRequest $request
     *
     * @return ITokenType
     * @throws \OAuth2\Exception\UnsupportedTokenTypeException
     */
    public function resolve(IRequest $request);


}
