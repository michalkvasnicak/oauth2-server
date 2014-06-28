<?php

namespace spec\OAuth2\Security;

use OAuth2\Storage\IAccessToken;
use OAuth2\Storage\IClient;
use OAuth2\Storage\IUser;
use PhpSpec\ObjectBehavior;
use Prophecy\Argument;

class SessionSpec extends ObjectBehavior
{

    function let(
        IAccessToken $accessToken
    ) {
        $this->beConstructedWith($accessToken);
    }


    function it_is_initializable()
    {
        $this->shouldHaveType('OAuth2\Security\Session');
    }

    function it_stores_access_token(
        IAccessToken $accessToken
    ) {
        $this->getAccessToken()->shouldReturn($accessToken);
    }

    function it_returns_user_from_access_token(
        IAccessToken $accessToken,
        IUser $user
    ) {
        $accessToken->getUser()->willReturn($user)->shouldBeCalled();
        $this->getUser()->shouldReturn($user);
    }


    function it_returns_client_from_access_token(
        IAccessToken $accessToken,
        IClient $client
    ) {
        $accessToken->getClient()->willReturn($client)->shouldBeCalled();
        $this->getClient()->shouldReturn($client);
    }


    function it_authorizes_access_to_given_scope(
        IAccessToken $accessToken
    ) {
        $accessToken->hasScope('edit')->willReturn(true)->shouldBeCalled();
        $this->isAllowed('edit')->shouldReturn(true);
    }

}
