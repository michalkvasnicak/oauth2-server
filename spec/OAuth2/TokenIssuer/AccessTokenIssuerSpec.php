<?php

namespace spec\OAuth2\TokenIssuer;

use OAuth2\GrantType\IGrantType;
use OAuth2\Resolver\IGrantTypeResolver;
use OAuth2\Http\IRequest;
use OAuth2\Storage\IAccessToken;
use PhpSpec\ObjectBehavior;
use Prophecy\Argument;

class AccessTokenIssuerSpec extends ObjectBehavior
{

    function let(
        IGrantTypeResolver $grantTypeResolver
    ) {
        $this->beConstructedWith($grantTypeResolver);
    }

    function it_is_initializable()
    {
        $this->shouldHaveType('OAuth2\TokenIssuer\AccessTokenIssuer');
    }


    function it_throws_exception_if_request_is_not_post(
        IRequest $request
    ) {
        $request->isMethod('post')->willReturn(false)->shouldBeCalled();
        $this->shouldThrow('OAuth2\Exception\InvalidHttpMethodException')->during('issueToken', [$request]);
    }


    function it_issues_access_token_using_grant_type_of_given_request(
        IRequest $request,
        IGrantTypeResolver $grantTypeResolver,
        IGrantType $grantType,
        IAccessToken $accessToken
    ) {
        $request->isMethod('post')->willReturn(true)->shouldBeCalled();
        $grantTypeResolver->resolve($request)->willReturn($grantType)->shouldBeCalled();
        $grantType->grant($request)->willReturn($accessToken)->shouldBeCalled();
        $this->issueToken($request)->shouldReturnAnInstanceOf('OAuth2\Storage\IAccessToken');
    }

}
