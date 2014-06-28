<?php

namespace spec\OAuth2\GrantType;

use OAuth2\GrantType\IGrantType;
use OAuth2\Http\IRequest;
use PhpSpec\ObjectBehavior;
use Prophecy\Argument;

class GrantTypeResolverSpec extends ObjectBehavior
{

    function it_is_initializable()
    {
        $this->shouldHaveType('OAuth2\Resolver\GrantTypeResolver');
        $this->shouldImplement('OAuth2\Resolver\IGrantTypeResolver');
    }


    function it_resolves_grant_type_for_request(
        IRequest $request,
        IGrantType $grantType
    ) {
        $grantType->match($request)->willReturn(true)->shouldBeCalled();
        $this->accept($grantType);
        $this->resolve($request)->shouldReturn($grantType);
    }


    function it_throws_exception_if_no_grant_type_matches_request(
        IRequest $request,
        IGrantType $grantType
    ) {
        $grantType->match($request)->willReturn(false)->shouldBeCalled();
        $this->accept($grantType);
        $this->shouldThrow('OAuth2\Exception\UnsupportedGrantTypeException')->during('resolve', [$request]);
    }

}
