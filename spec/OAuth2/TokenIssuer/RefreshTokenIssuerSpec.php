<?php

namespace spec\OAuth2\TokenIssuer;

use OAuth2\Storage\IAccessToken;
use OAuth2\Storage\IClient;
use OAuth2\Storage\IRefreshToken;
use OAuth2\Storage\IRefreshTokenStorage;
use OAuth2\Storage\IScope;
use OAuth2\Storage\IUser;
use PhpSpec\ObjectBehavior;
use Prophecy\Argument;

class RefreshTokenIssuerSpec extends ObjectBehavior
{

    function let(IRefreshTokenStorage $refreshTokenStorage)
    {
        $this->beConstructedWith($refreshTokenStorage);
    }


    function it_is_initializable()
    {
        $this->shouldHaveType('OAuth2\TokenIssuer\RefreshTokenIssuer');
    }

    function it_issues_refresh_token_for_given_access_token(
        IRefreshTokenStorage $refreshTokenStorage,
        IAccessToken $accessToken,
        IRefreshToken $refreshToken,
        IUser $user,
        IClient $client,
        IScope $scope
    ) {
        $accessToken->getUser()->willReturn($user)->shouldBeCalled();
        $accessToken->getClient()->willReturn($client)->shouldBeCalled();
        $accessToken->getScopes()->willReturn([$scope])->shouldBeCalled();
        $refreshTokenStorage->generate($user, $client, [$scope])->willReturn($refreshToken)->shouldBeCalled();
        $this->issueToken($accessToken)->shouldReturnAnInstanceOf('OAuth2\Storage\IRefreshToken');
    }

}
