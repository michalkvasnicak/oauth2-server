<?php

namespace spec\OAuth2\GrantType;

use OAuth2\Exception\InvalidGrantException;
use OAuth2\Exception\MissingParameterException;
use OAuth2\Exception\UnauthorizedClientException;
use OAuth2\Http\IRequest;
use OAuth2\Resolver\IScopeResolver;
use OAuth2\Security\IClientAuthenticator;
use OAuth2\Storage\IAccessToken;
use OAuth2\Storage\IAccessTokenStorage;
use OAuth2\Storage\IClient;
use OAuth2\Storage\IRefreshToken;
use OAuth2\Storage\IRefreshTokenStorage;
use OAuth2\Storage\IScope;
use OAuth2\Storage\IUser;
use PhpSpec\ObjectBehavior;
use Prophecy\Argument;

class RefreshTokenSpec extends ObjectBehavior
{

    function let(
        IRefreshTokenStorage $refreshTokenStorage,
        IAccessTokenStorage $accessTokenStorage,
        IClientAuthenticator $clientAuthenticator,
        IScopeResolver $scopeResolver
    ) {
        $this->beConstructedWith(
            $clientAuthenticator,
            $refreshTokenStorage,
            $accessTokenStorage,
            $scopeResolver
        );
    }

    function it_is_initializable()
    {
        $this->shouldHaveType('OAuth2\GrantType\RefreshToken');
        $this->shouldImplement('OAuth2\GrantType\IGrantType');
    }


    function it_matches_against_request(
        IRequest $request
    ) {
        $request->request('grant_type')->willReturn('refresh_token')->shouldBeCalled();
        $this->match($request)->shouldReturn(true);

        $request->request('grant_type')->willReturn('pom')->shouldBeCalled();
        $this->match($request)->shouldReturn(false);
    }


    function it_throws_exception_on_missing_refresh_token(
        IRequest $request
    ) {
        $request->request('refresh_token')->willReturn(null)->shouldBeCalled();
        $this->shouldThrow(new MissingParameterException("Parameter 'refresh_token' is missing."))->during('grant', [$request]);
    }


    function it_throws_exception_on_not_existing_refresh_token(
        IRequest $request,
        IRefreshTokenStorage $refreshTokenStorage
    ) {
        $request->request('refresh_token')->willReturn('pom')->shouldBeCalled();
        $refreshTokenStorage->get('pom')->willReturn(null)->shouldBeCalled();
        $this->shouldThrow(new InvalidGrantException("Invalid refresh token."))->during('grant', [$request]);
    }


    function it_throws_exception_on_refresh_token_issued_to_another_client(
        IRequest $request,
        IRefreshTokenStorage $refreshTokenStorage,
        IRefreshToken $refreshToken,
        IClient $client1,
        IClient $client2,
        IClientAuthenticator $clientAuthenticator
    ) {
        $request->request('refresh_token')->willReturn('pom')->shouldBeCalled();
        $refreshTokenStorage->get('pom')->willReturn($refreshToken)->shouldBeCalled();
        $refreshToken->getClient()->willReturn($client1)->shouldBeCalled();
        $clientAuthenticator->authenticate($request)->willReturn($client2)->shouldBeCalled();
        $client1->getId()->willReturn('test')->shouldBeCalled();
        $client2->getId()->willReturn('nottest')->shouldBeCalled();
        $this->shouldThrow(new InvalidGrantException('Invalid refresh token.'))->during('grant', [$request]);
    }


    function it_throws_exception_on_expired_refresh_token(
        IRequest $request,
        IRefreshTokenStorage $refreshTokenStorage,
        IRefreshToken $refreshToken,
        IClient $client,
        IClientAuthenticator $clientAuthenticator
    ) {
        $request->request('refresh_token')->willReturn('pom')->shouldBeCalled();
        $refreshTokenStorage->get('pom')->willReturn($refreshToken)->shouldBeCalled();
        $refreshToken->getClient()->willReturn($client)->shouldBeCalled();
        $clientAuthenticator->authenticate($request)->willReturn($client)->shouldBeCalled();
        $client->getId()->willReturn('test')->shouldBeCalled();
        $client->isAllowedToUse($this)->willReturn(true)->shouldBeCalled();
        $refreshToken->getExpiresAt()->willReturn(1)->shouldBeCalled();
        $this->shouldThrow(new InvalidGrantException('Refresh token has expired.'))->during('grant', [$request]);
    }


    function it_throws_exception_if_client_is_not_allowed_to_use_this_grant_type(
        IRequest $request,
        IRefreshTokenStorage $refreshTokenStorage,
        IRefreshToken $refreshToken,
        IClient $client,
        IClientAuthenticator $clientAuthenticator
    ) {
        $request->request('refresh_token')->willReturn('pom')->shouldBeCalled();
        $refreshTokenStorage->get('pom')->willReturn($refreshToken)->shouldBeCalled();
        $refreshToken->getClient()->willReturn($client)->shouldBeCalled();
        $clientAuthenticator->authenticate($request)->willReturn($client)->shouldBeCalled();
        $client->getId()->willReturn('test')->shouldBeCalled();
        $client->isAllowedToUse($this)->willReturn(false)->shouldBeCalled();
        $this->shouldThrow(new UnauthorizedClientException('Client can not use this grant type.'))->during('grant', [$request]);
    }


    function it_issues_an_access_token(
        IRequest $request,
        IRefreshToken $refreshToken,
        IRefreshTokenStorage $refreshTokenStorage,
        IAccessTokenStorage $accessTokenStorage,
        IAccessToken $accessToken,
        IUser $user,
        IClient $client,
        IScope $scope1,
        IScope $scope2,
        IScopeResolver $scopeResolver,
        IClientAuthenticator $clientAuthenticator
    ) {
        $scopes = [$scope1, $scope2];

        $request->request('refresh_token')->willReturn('pom')->shouldBeCalled();
        $refreshTokenStorage->get('pom')->willReturn($refreshToken)->shouldBeCalled();
        $refreshToken->getClient()->willReturn($client)->shouldBeCalled();
        $clientAuthenticator->authenticate($request)->willReturn($client)->shouldBeCalled();
        $client->getId()->willReturn('test')->shouldBeCalled();
        $client->isAllowedToUse($this)->willReturn(true)->shouldBeCalled();
        $refreshToken->getExpiresAt()->willReturn(time() + 100)->shouldBeCalled();
        $refreshToken->getScopes()->willReturn($scopes)->shouldBeCalled();
        $request->request('scope')->willReturn(null)->shouldBeCalled();
        $scopeResolver->intersect(null, $scopes)->willReturn($scopes)->shouldBeCalled();
        $refreshToken->getUser()->willReturn($user)->shouldBeCalled();
        $accessTokenStorage->generate($user, $client, $scopes)->willReturn($accessToken)->shouldBeCalled();
        $this->grant($request)->shouldReturnAnInstanceOf('OAuth2\Storage\IAccessToken');
    }

}
