<?php

namespace OAuth2\Resolver;

use OAuth2\Exception\InvalidScopeException;
use OAuth2\Storage\IScope;
use Prophecy\Exception\InvalidArgumentException;

/**
 * @author Michal Kvasničák <michal.kvasnicak@mink.sk>
 */
class ScopeResolver implements IScopeResolver
{

    /** @var \SplObjectStorage  */
    private $defaultScopes;


    public function __construct()
    {
        $this->defaultScopes = new \SplObjectStorage();
    }


    /**
     * Adds scope to default scopes
     *
     * @param IScope $scope
     */
    public function addDefaultScope(IScope $scope)
    {
        if (!$this->defaultScopes->contains($scope)) {
            $this->defaultScopes->attach($scope);
        } else {
            throw new \InvalidArgumentException("Scope '{$scope->getId()}' is already registered as default scope.");
        }
    }


    /**
     * Gets default scopes which are used if client is not associated with any
     *
     * @return IScope[]
     */
    public function getDefaultScopes()
    {
        return iterator_to_array($this->defaultScopes);
    }


    /**
     * Are all requested scopes in available scopes?
     *
     * If all requested scopes are in available scopes, returns requested scopes
     * If none or some of requested scopes are not available scopes throws exception
     * If requested scopes are in available scopes, returns intersection of these scopes
     * If requested scopes are empty, returns available scopes
     *
     * @param array|string|null $requestedScopes
     * @param array|\Traversable|IScope[] $availableScopes
     *
     * @return IScope[]
     * @throws InvalidScopeException
     */
    public function intersect($requestedScopes, $availableScopes = [])
    {
        if ($availableScopes instanceof \Traversable) {
            $availableScopes = iterator_to_array($availableScopes);
        } else if (!is_array($availableScopes)) {
            throw new \InvalidArgumentException(
                'Available scopes has to be array or traversable. But ' . gettype($availableScopes) . ' was given.'
            );
        }

        $intersection = [];

        if (empty($availableScopes)) {
            throw new InvalidArgumentException('Available scopes has to be array of OAuth2\Storage\IScope instances. Empty was given.');
        }

        // validate available scopes
        foreach ($availableScopes as $scope) {
            if (!$scope instanceof IScope) {
                throw new \InvalidArgumentException('Available scopes has to be array of OAuth2\Storage\IScope instances.');
            }
        }

        if (empty($requestedScopes)) {
            return $availableScopes;
        } else if (is_string($requestedScopes)) {
            $requestedScopes = explode(' ', $requestedScopes);
        } else if ($requestedScopes instanceof IScope) {
            $requestedScopes = [$requestedScopes->getId()];
        } else if ($requestedScopes instanceof \Traversable) {
            $requestedScopes = $this->parseScopeArray(iterator_to_array($requestedScopes));
        } else if (is_array($requestedScopes)) {
            $requestedScopes = $this->parseScopeArray($requestedScopes);
        }

        // find intersection
        foreach ($requestedScopes as $requestedScope) {
            foreach ($availableScopes as $index => $availableScope) {
                if ($availableScope->getId() === $requestedScope) {
                    // unset scope from available scopes
                    unset($availableScopes[$index]);
                    $intersection[] = $availableScope;
                    continue 2;
                }
            }

            throw new InvalidScopeException("Scope '$requestedScope' is invalid.");
        }

        return $intersection;
    }


    /**
     * Parses scopes from array of scopes and returns array of scope identifiers
     *
     * @param string[] $scopes
     * @return string[]
     * @throws \InvalidArgumentException
     */
    protected function parseScopeArray(array $scopes)
    {
        $parsedScopes = [];

        foreach ($scopes as $scope) {
            if (is_string($scope) && $scope != '') {
                $parsedScopes[] = $scope;
            } else if ($scope instanceof IScope) {
                $parsedScopes[] =  $scope->getId();
            } else {
                throw new \InvalidArgumentException('Scopes has to be array of strings or OAuth2\Storage\IScope instances.');
            }
        }

        return $parsedScopes;
    }

}
