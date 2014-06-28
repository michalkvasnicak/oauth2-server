<?php

namespace spec\OAuth2\Security;

use OAuth2\Http\IRequest;
use OAuth2\Storage\IAccessToken;
use OAuth2\Storage\IAccessTokenStorage;
use OAuth2\TokenType\ITokenType;
use OAuth2\Resolver\ITokenTypeResolver;
use PhpSpec\ObjectBehavior;
use Prophecy\Argument;

class AuthenticatorSpec extends ObjectBehavior
{

    function let(
        ITokenTypeResolver $tokenTypeResolver,
        IAccessTokenStorage $accessTokenStorage
    ) {
        $this->beConstructedWith($tokenTypeResolver, $accessTokenStorage);
    }


    function it_is_initializable()
    {
        $this->shouldHaveType('OAuth2\Security\Authenticator');
    }


    function it_authenticates_request_and_returns_session_on_success(
        IRequest $request,
        ITokenTypeResolver $tokenTypeResolver,
        ITokenType $tokenType,
        IAccessTokenStorage $accessTokenStorage,
        IAccessToken $accessToken
    ) {
        $tokenTypeResolver->resolve($request)->willReturn($tokenType)->shouldBeCalled();
        $tokenType->getAccessToken()->willReturn('abcd')->shouldBeCalled();
        $accessTokenStorage->get('abcd')->willReturn($accessToken)->shouldBeCalled();
        $this->authenticate($request)->shouldReturnAnInstanceOf('OAuth2\Security\Session');
    }


    function it_authenticates_request_and_throws_exception_if_access_token_does_not_exist(
        IRequest $request,
        ITokenTypeResolver $tokenTypeResolver,
        ITokenType $tokenType,
        IAccessTokenStorage $accessTokenStorage
    ) {
        $tokenTypeResolver->resolve($request)->willReturn($tokenType)->shouldBeCalled();
        $tokenType->getAccessToken()->willReturn('abcd')->shouldBeCalled();
        $accessTokenStorage->get('abcd')->willReturn(null)->shouldBeCalled();

        $this->shouldThrow('OAuth2\Exception\NotAuthenticatedException')->during('authenticate', [$request]);
    }

}
