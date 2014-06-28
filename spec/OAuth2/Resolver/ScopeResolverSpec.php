<?php

namespace spec\OAuth2\Resolver;

use OAuth2\Exception\InvalidScopeException;
use OAuth2\Storage\IScope;
use PhpSpec\ObjectBehavior;
use Prophecy\Argument;

class ScopeResolverSpec extends ObjectBehavior
{
    function it_is_initializable()
    {
        $this->shouldHaveType('OAuth2\Resolver\ScopeResolver');
        $this->shouldImplement('OAuth2\Resolver\IScopeResolver');
    }


    function it_throws_exception_on_registering_same_scope_again_as_default(
        IScope $scope
    ) {
        $scope->getId()->willReturn('same');

        $this->addDefaultScope($scope);
        $this
            ->shouldThrow(new \InvalidArgumentException("Scope 'same' is already registered as default scope."))
            ->during('addDefaultScope', [$scope]);
    }

    function it_returns_default_scopes(IScope $scope1, IScope $scope2)
    {
        $this->getDefaultScopes()->shouldReturn([]);
        $this->addDefaultScope($scope1);
        $this->addDefaultScope($scope2);
        $this->getDefaultScopes()->shouldReturn([$scope1, $scope2]);
    }


    function it_returns_available_scopes_if_requested_is_null_or_empty_using_intersection(
        IScope $scope
    ) {
        $this->intersect(null, [$scope])->shouldReturn([$scope]);
        $this->intersect('', [$scope])->shouldReturn([$scope]);
    }


    function it_returns_available_scopes_if_requested_is_array_of_string_using_intersection(
        IScope $scope
    ) {
        $scope->getId()->willReturn('scope1')->shouldBeCalled();
        $this->intersect(['scope1'], [$scope])->shouldReturn([$scope]);
    }


    function it_returns_available_scopes_if_requested_is_array_of_scopes_using_intersection(
        IScope $scope
    ) {
        $scope->getId()->willReturn('scope1')->shouldBeCalled();
        $this->intersect([$scope], [$scope])->shouldReturn([$scope]);
    }


    function it_returns_available_scopes_if_requested_is_scope_using_intersection(
        IScope $scope
    ) {
        $scope->getId()->willReturn('scope1')->shouldBeCalled();
        $this->intersect($scope, [$scope])->shouldReturn([$scope]);
    }


    function it_returns_requested_and_available_scopes_if_available_are_subset_of_requested_scopes_using_intersection(
        IScope $scope1,
        IScope $scope2,
        IScope $scope3,
        IScope $scope4
    )
    {
        $scope1->getId()->willReturn('scope1');
        $scope2->getId()->willReturn('scope2');
        $scope3->getId()->willReturn('scope3');
        $scope4->getId()->willReturn('scope4');

        $this->intersect(
            'scope1 scope2 scope3',
            [$scope1, $scope2, $scope3, $scope4]
        )->shouldReturn([$scope1, $scope2, $scope3]);
    }


    function it_throws_exception_if_requested_scopes_contains_scope_that_is_not_in_available_scopesusing_intersection(
        IScope $scope1,
        IScope $scope2,
        IScope $scope3,
        IScope $scope4
    ) {
        $scope1->getId()->willReturn('scope1');
        $scope2->getId()->willReturn('scope2');
        $scope3->getId()->willReturn('scope3');
        $scope4->getId()->willReturn('scope4');

        $this
            ->shouldThrow(new InvalidScopeException("Scope 'unknown' is invalid."))
            ->during('intersect', ['scope1 scope2 unknown', [$scope1, $scope2, $scope3, $scope4]]);
    }


    function it_throws_exception_if_invalid_argument_was_given_to_intersection(
        IScope $scope
    ) {
        $this->shouldThrow('InvalidArgumentException')->during('intersect', [[true], [$scope]]);
    }


    function it_throws_exception_if_empty_available_scopes_was_given_to_intersection()
    {
        $this->shouldThrow('InvalidArgumentException')->during('intersect', [null, []]);
    }

}
