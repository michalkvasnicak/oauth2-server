<?php

namespace spec\OAuth2\Resolver;

use OAuth2\Http\IRequest;
use OAuth2\TokenType\ITokenType;
use PhpSpec\ObjectBehavior;
use Prophecy\Argument;

class TokenTypeResolverSpec extends ObjectBehavior
{

    function it_is_initializable()
    {
        $this->shouldHaveType('OAuth2\Resolver\TokenTypeResolver');
        $this->shouldImplement('OAuth2\Resolver\ITokenTypeResolver');
    }


    function it_should_throw_exception_if_no_token_types_are_registered(
        IRequest $request
    ) {
        $this->shouldThrow('OAuth2\Exception\UnsupportedTokenTypeException')->during('resolve', [$request]);
    }


    function it_should_match_request_against_accepted_token_types_and_throw_exception_if_none_matches(
        ITokenType $tokenType,
        IRequest $request
    ) {
        $tokenType->match($request)->willReturn(false)->shouldBeCalled();
        $this->accept($tokenType);
        $this->shouldThrow('OAuth2\Exception\UnsupportedTokenTypeException')->during('resolve', [$request]);
    }


    function it_should_return_token_type_on_match(
        ITokenType $tokenType,
        IRequest $request
    ) {
        $tokenType->match($request)->willReturn(true)->shouldBeCalled();
        $this->accept($tokenType);
        $this->resolve($request)->shouldReturn($tokenType);
    }

}
