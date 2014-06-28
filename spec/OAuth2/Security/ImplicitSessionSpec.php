<?php

namespace spec\OAuth2\Security;

use OAuth2\Storage\IAccessToken;
use OAuth2\Storage\IClient;
use OAuth2\Storage\IScope;
use OAuth2\Storage\IUser;
use PhpSpec\ObjectBehavior;
use Prophecy\Argument;

class ImplicitSessionSpec extends ObjectBehavior
{

    function let(
        IAccessToken $accessToken
    ) {
        $this->beConstructedWith($accessToken, 'Bearer', 'http://google.com', 'state');
    }


    function it_is_initializable()
    {
        $this->shouldHaveType('OAuth2\Security\ImplicitSession');
        $this->shouldImplement('OAuth2\Security\IAuthorizationSession');
    }


    function it_should_return_redirect_uri(
        IAccessToken $accessToken,
        IScope $scope1,
        IScope $scope2
    ) {
        $accessToken->getExpiresAt()->willReturn(time() + 3600)->shouldBeCalled();
        $accessToken->getId()->willReturn('abcde')->shouldBeCalled();
        $accessToken->getScopes()->willReturn([$scope1, $scope2])->shouldBeCalled();
        $scope1->getId()->willReturn('scope1')->shouldBeCalled();
        $scope2->getId()->willReturn('scope2')->shouldBeCalled();

        $this->getRedirectUri()->shouldReturn('http://google.com#access_token=abcde&expires_in=3600&scope=scope1+scope2&state=state&token_type=Bearer');
    }


    function it_should_return_access_token(
        IAccessToken $accessToken
    ) {
        $this->getAccessToken()->shouldReturn($accessToken);
    }


    function it_should_return_state()
    {
        $this->getState()->shouldReturn('state');
    }


    function it_should_return_user_from_access_token(
        IAccessToken $accessToken,
        IUser $user
    ) {
        $accessToken->getUser()->willReturn($user)->shouldBeCalled();
        $this->getUser()->shouldReturn($user);
    }


    function it_should_return_client_from_access_token(
        IAccessToken $accessToken,
        IClient $client
    ) {
        $accessToken->getClient()->willReturn($client)->shouldBeCalled();
        $this->getClient()->shouldReturn($client);
    }


    function it_should_return_scopes_from_access_token(
        IAccessToken $accessToken
    ) {
        $accessToken->getScopes()->willReturn([])->shouldBeCalled();
        $this->getScopes()->shouldReturn([]);
    }

}
