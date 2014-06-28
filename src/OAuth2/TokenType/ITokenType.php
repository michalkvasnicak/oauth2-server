<?php

namespace OAuth2\TokenType;

use OAuth2\Http\IRequest;

/**
 * @author Michal Kvasničák <michal.kvasnicak@mink.sk>
 */
interface ITokenType 
{

    /**
     * Gets token type name
     *
     * @return string
     */
    public function getName();


    /**
     * Gets access token identifier
     *
     * @return string
     */
    public function getAccessToken();


    /**
     * Matches token type against request and returns if it matches
     *
     * @param IRequest $request
     *
     * @return boolean
     * @throws \OAuth2\Exception\MalformedTokenException
     */
    public function match(IRequest $request);

}
