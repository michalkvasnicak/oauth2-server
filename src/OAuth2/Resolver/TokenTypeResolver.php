<?php

namespace OAuth2\Resolver;

use OAuth2\Http\IRequest;
use OAuth2\Exception\UnsupportedTokenTypeException;
use OAuth2\TokenType\ITokenType;

/**
 * @author Michal Kvasničák <michal.kvasnicak@mink.sk>
 */
class TokenTypeResolver implements ITokenTypeResolver
{

    /**
     * @var ITokenType[]
     */
    protected $tokenTypes = [];


    /**
     * Adds accepted token type
     *
     * @param ITokenType $tokenType
     */
    public function accept(ITokenType $tokenType)
    {
        $this->tokenTypes[] = $tokenType;
    }


    /**
     * Resolves token type from request
     *
     * @param IRequest $request
     *
     * @return ITokenType
     * @throws \OAuth2\Exception\UnsupportedTokenTypeException
     */
    public function resolve(IRequest $request)
    {
        foreach ($this->tokenTypes as $tokenType) {
            if ($tokenType->match($request)) {
                return $tokenType;
            }
        }

        throw new UnsupportedTokenTypeException;
    }
}
