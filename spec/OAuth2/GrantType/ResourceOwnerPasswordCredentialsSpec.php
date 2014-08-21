<?php

namespace spec\OAuth2\GrantType;

use OAuth2\Exception\InvalidGrantException;
use OAuth2\Exception\InvalidRequestException;
use OAuth2\Exception\InvalidScopeException;
use OAuth2\Exception\UnauthorizedClientException;
use OAuth2\Http\IRequest;
use OAuth2\Resolver\IScopeResolver;
use OAuth2\Security\IClientAuthenticator;
use OAuth2\Security\IUserAuthenticator;
use OAuth2\Storage\IAccessToken;
use OAuth2\Storage\IAccessTokenStorage;
use OAuth2\Storage\IClient;
use OAuth2\Storage\IScope;
use OAuth2\Storage\IUser;
use PhpSpec\ObjectBehavior;
use Prophecy\Argument;

class ResourceOwnerPasswordCredentialsSpec extends ObjectBehavior
{

    function let(
        IClientAuthenticator $clientAuthenticator,
        IUserAuthenticator $userAuthenticator,
        IAccessTokenStorage $accessTokenStorage,
        IScopeResolver $scopeResolver
    ) {
        $this->beConstructedWith($clientAuthenticator, $userAuthenticator, $accessTokenStorage, $scopeResolver);
    }

    function it_is_initializable()
    {
        $this->shouldHaveType('OAuth2\GrantType\ResourceOwnerPasswordCredentials');
        $this->shouldImplement('OAuth2\GrantType\IGrantType');
    }

    function it_matches_against_request(
        IRequest $request
    ) {
        $request->request('grant_type')->willReturn('password')->shouldBeCalled();
        $this->match($request)->shouldReturn(true);

        $request->request('grant_type')->willReturn('pom')->shouldBeCalled();
        $this->match($request)->shouldReturn(false);
    }


    function it_throws_exception_on_missing_username(
        IRequest $request,
        IClientAuthenticator $clientAuthenticator
    ) {
        $request->request('username')->willReturn(null)->shouldBeCalled();
        $request->request('password')->willReturn(null)->shouldBeCalled();
        $clientAuthenticator->authenticate($request)->shouldNotBeCalled();

        $this
            ->shouldThrow(new InvalidRequestException('Username and password are required.'))
            ->during('grant', [$request]);
    }


    function it_throws_exception_if_client_is_not_allowed_to_use_this_grant_type(
        IRequest $request,
        IClientAuthenticator $clientAuthenticator,
        IUserAuthenticator $userAuthenticator,
        IClient $client
    ) {
        $request->request('username')->willReturn('root')->shouldBeCalled();
        $request->request('password')->willReturn('p')->shouldBeCalled();
        $clientAuthenticator->authenticate($request)->willReturn($client)->shouldBeCalled();
        $client->isAllowedToUse($this)->willReturn(false)->shouldBeCalled();
        $userAuthenticator->authenticate('root', 'p')->shouldNotBeCalled();

        $this
            ->shouldThrow(new UnauthorizedClientException('Client can not use this grant type.'))
            ->during('grant', [$request]);
    }


    function it_throws_exception_on_invalid_credentials(
        IRequest $request,
        IClientAuthenticator $clientAuthenticator,
        IUserAuthenticator $userAuthenticator,
        IClient $client
    ) {
        $request->request('username')->willReturn('root')->shouldBeCalled();
        $request->request('password')->willReturn('p')->shouldBeCalled();
        $clientAuthenticator->authenticate($request)->willReturn($client)->shouldBeCalled();
        $client->isAllowedToUse($this)->willReturn(true)->shouldBeCalled();
        $userAuthenticator->authenticate('root', 'p')->willReturn(null)->shouldBeCalled();

        $this
            ->shouldThrow(new InvalidGrantException('Invalid user credentials.'))
            ->during('grant', [$request]);
    }


    function it_throws_exception_if_client_and_default_scopes_are_not_set(
        IRequest $request,
        IClientAuthenticator $clientAuthenticator,
        IUserAuthenticator $userAuthenticator,
        IScopeResolver $scopeResolver,
        IUser $user,
        IClient $client
    ) {
        $request->request('username')->willReturn('root')->shouldBeCalled();
        $request->request('password')->willReturn('p')->shouldBeCalled();
        $clientAuthenticator->authenticate($request)->willReturn($client)->shouldBeCalled();
        $client->isAllowedToUse($this)->willReturn(true)->shouldBeCalled();
        $userAuthenticator->authenticate('root', 'p')->willReturn($user)->shouldBeCalled();
        $request->request('scope')->shouldBeCalled();
        $user->getScopes()->willReturn([])->shouldBeCalled();
        $scopeResolver->getDefaultScopes()->willReturn([])->shouldBeCalled();

        $this
            ->shouldThrow(new InvalidScopeException('Scope parameter has to be specified.'))
            ->during('grant', [$request]);
    }


    function it_issues_an_access_token_using_user_scopes(
        IRequest $request,
        IClientAuthenticator $clientAuthenticator,
        IUserAuthenticator $userAuthenticator,
        IScopeResolver $scopeResolver,
        IUser $user,
        IClient $client,
        IScope $scope,
        IAccessTokenStorage $accessTokenStorage,
        IAccessToken $accessToken
    ) {
        $request->request('username')->willReturn('root')->shouldBeCalled();
        $request->request('password')->willReturn('p')->shouldBeCalled();
        $clientAuthenticator->authenticate($request)->willReturn($client)->shouldBeCalled();
        $client->isAllowedToUse($this)->willReturn(true)->shouldBeCalled();
        $userAuthenticator->authenticate('root', 'p')->willReturn($user)->shouldBeCalled();
        $request->request('scope')->willReturn(null)->shouldBeCalled();
        $user->getScopes()->willReturn([$scope])->shouldBeCalled();
        $scopeResolver->getDefaultScopes()->shouldNotBeCalled();
        $scopeResolver->intersect(null, [$scope])->willReturn([$scope])->shouldBeCalled();
        $accessTokenStorage->generate($user, $client, [$scope])->willReturn($accessToken)->shouldBeCalled();

        $this->grant($request)->shouldReturn($accessToken);
    }


    function it_issues_an_access_token_using_default_scopes(
        IRequest $request,
        IClientAuthenticator $clientAuthenticator,
        IUserAuthenticator $userAuthenticator,
        IScopeResolver $scopeResolver,
        IUser $user,
        IClient $client,
        IScope $scope,
        IAccessTokenStorage $accessTokenStorage,
        IAccessToken $accessToken
    ) {
        $request->request('username')->willReturn('root')->shouldBeCalled();
        $request->request('password')->willReturn('p')->shouldBeCalled();
        $clientAuthenticator->authenticate($request)->willReturn($client)->shouldBeCalled();
        $client->isAllowedToUse($this)->willReturn(true)->shouldBeCalled();
        $userAuthenticator->authenticate('root', 'p')->willReturn($user)->shouldBeCalled();
        $request->request('scope')->willReturn(null)->shouldBeCalled();
        $user->getScopes()->willReturn([])->shouldBeCalled();
        $scopeResolver->getDefaultScopes()->willReturn([$scope])->shouldBeCalled();
        $scopeResolver->intersect(null, [$scope])->willReturn([$scope])->shouldBeCalled();
        $accessTokenStorage->generate($user, $client, [$scope])->willReturn($accessToken)->shouldBeCalled();

        $this->grant($request)->shouldReturn($accessToken);
    }

}
