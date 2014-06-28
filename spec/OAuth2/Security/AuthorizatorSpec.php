<?php

namespace spec\OAuth2\Security;

use OAuth2\GrantType\IAuthorizationGrantType;
use OAuth2\GrantType\IGrantType;
use OAuth2\Resolver\IGrantTypeResolver;
use OAuth2\Http\IRequest;
use OAuth2\Security\AuthorizationCodeSession;
use OAuth2\Storage\IUser;
use PhpSpec\ObjectBehavior;
use Prophecy\Argument;

class AuthorizatorSpec extends ObjectBehavior
{

    function let(IGrantTypeResolver $grantTypeResolver)
    {
        $this->beConstructedWith($grantTypeResolver);
    }


    function it_is_initializable()
    {
        $this->shouldHaveType('OAuth2\Security\Authorizator');
    }


    function it_returns_authorization_session_on_success(
        IGrantTypeResolver $grantTypeResolver,
        IRequest $request,
        IAuthorizationGrantType $authorizationGrantType,
        AuthorizationCodeSession $authorizationSession,
        IUser $user
    ) {
        $grantTypeResolver->resolve($request)->willReturn($authorizationGrantType)->shouldBeCalled();
        $authorizationGrantType->authorize($request, $user)->willReturn($authorizationSession)->shouldBeCalled();
        $this->authorize($request, $user)->shouldReturnAnInstanceOf('OAuth2\Security\AuthorizationCodeSession');
    }


    function it_throws_exception_on_invalid_grant_type(
        IGrantTypeResolver $grantTypeResolver,
        IRequest $request,
        IGrantType $grantType,
        IUser $user
    ) {
        $grantTypeResolver->resolve($request)->willReturn($grantType)->shouldBeCalled();
        $this->shouldThrow('OAuth2\Exception\UnsupportedResponseTypeException')->during('authorize', [$request, $user]);
    }

}
