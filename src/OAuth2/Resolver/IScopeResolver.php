<?php

namespace OAuth2\Resolver;

use OAuth2\Exception\InvalidScopeException;
use OAuth2\Storage\IScope;

/**
 * @author Michal Kvasničák <michal.kvasnicak@mink.sk>
 */
interface IScopeResolver 
{

    /**
     * Gets default scopes which are used if client is not associated with any
     *
     * @return IScope[]
     */
    public function getDefaultScopes();


    /**
     * Are all requested scopes in available scopes?
     *
     * If all requested scopes are in available scopes, returns requested scopes
     * If none or some of requested scopes are not available scopes throws exception
     * If requested scopes are in available scopes, returns intersection of these scopes
     * If requested scopes are empty, returns available scopes
     *
     * @param array|string|null $requestedScopes
     * @param IScope[] $availableScopes
     *
     * @return IScope[]
     * @throws InvalidScopeException
     */
    public function intersect($requestedScopes, array $availableScopes = []);

}
