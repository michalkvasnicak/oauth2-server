<?php

namespace spec\OAuth2\Security;

use OAuth2\Storage\IAuthorizationCode;
use PhpSpec\ObjectBehavior;
use Prophecy\Argument;

class AuthorizationCodeSessionSpec extends ObjectBehavior
{

    function let(IAuthorizationCode $authorizationCode)
    {
        $this->beConstructedWith($authorizationCode);
    }

    function it_is_initializable()
    {
        $this->shouldHaveType('OAuth2\Security\AuthorizationCodeSession');
        $this->shouldImplement('OAuth2\Security\IAuthorizationSession');
    }


    function it_should_return_authorization_code(
        IAuthorizationCode $authorizationCode
    ) {
        $this->getAuthorizationCode()->shouldReturn($authorizationCode);
    }


    function it_should_return_user_from_authorization_code(
        IAuthorizationCode $authorizationCode
    ) {
        $authorizationCode->getUser()->willReturn(true)->shouldBeCalled();
        $this->getUser()->shouldReturn(true);
    }


    function it_should_return_client_from_authorization_code(
        IAuthorizationCode $authorizationCode
    ) {
        $authorizationCode->getClient()->willReturn(true)->shouldBeCalled();
        $this->getClient()->shouldReturn(true);
    }


    function it_should_return_scopes_from_authorization_code(
        IAuthorizationCode $authorizationCode
    ) {
        $authorizationCode->getScopes()->willReturn([])->shouldBeCalled();
        $this->getScopes()->shouldReturn([]);
    }


    function it_should_return_redirect_uri_from_authorization_code(
        IAuthorizationCode $authorizationCode
    ) {
        $authorizationCode->getId()->willReturn('pompom')->shouldBeCalled();
        $authorizationCode->getRedirectUri()->willReturn('http://google.com')->shouldBeCalled();
        $authorizationCode->getState()->willReturn('pom')->shouldBeCalled();
        $this->getRedirectUri()->shouldReturn('http://google.com?code=pompom&state=pom');
    }


    function it_should_return_state_from_authorization_code(
        IAuthorizationCode $authorizationCode
    ) {
        $authorizationCode->getState()->willReturn(null)->shouldBeCalled();
        $this->getState()->shouldReturn(null);
    }

}
