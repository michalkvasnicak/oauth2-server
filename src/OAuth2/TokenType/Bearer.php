<?php

namespace OAuth2\TokenType;

use OAuth2\Exception\InvalidHttpMethodException;
use OAuth2\Http\IRequest;
use OAuth2\Exception\InvalidContentTypeException;
use OAuth2\Exception\MalformedTokenException;

/**
 * @author Michal Kvasničák <michal.kvasnicak@mink.sk>
 */
class Bearer implements ITokenType
{

    protected $identifier;


    /**
     * Gets access token identifier
     *
     * @return string
     */
    public function getAccessToken()
    {
        return $this->identifier;
    }

    /**
     * Gets token type name
     *
     * @return string
     */
    public function getName()
    {
        return 'Bearer';
    }


    /**
     * Matches token type against request and returns if it matches
     *
     * @param IRequest $request
     *
     * @throws \OAuth2\Exception\InvalidContentTypeException
     * @throws \OAuth2\Exception\InvalidHttpMethodException
     * @throws \OAuth2\Exception\MalformedTokenException
     * @return boolean
     */
    public function match(IRequest $request)
    {
        // first check request for authorization header
        $header = $request->headers('authorization');

        if ($header) {
            if (!preg_match('~Bearer\s(\S+)~', $header, $matches)) {
                throw new MalformedTokenException;
            }

            $this->identifier = $matches[1];
            return true;
        }

        // if is POST check for request (POST BODY) parameters
        if ($accessToken = $request->request('access_token')) {
            if (!($request->isMethod('post') || $request->isMethod('put'))) {
                throw new InvalidHttpMethodException;
            }

            $contentType = $request->headers('content_type');

            if (!$contentType || strpos($contentType, 'application/x-www-form-urlencoded') !== 0) {
                throw new InvalidContentTypeException;
            }

            $this->identifier = $accessToken;
            return true;
        }

        // check query for access token
        if ($accessToken = $request->query('access_token')) {
            $this->identifier = $accessToken;
            return true;
        }

        return false;
    }

}
