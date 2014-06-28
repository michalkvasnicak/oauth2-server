<?php

namespace spec\OAuth2\GrantType;

use OAuth2\Exception\InvalidClientException;
use OAuth2\Exception\InvalidScopeException;
use OAuth2\Exception\UnauthorizedClientException;
use OAuth2\Http\IRequest;
use OAuth2\Resolver\IScopeResolver;
use OAuth2\Security\IClientAuthenticator;
use OAuth2\Storage\IAccessToken;
use OAuth2\Storage\IAccessTokenStorage;
use OAuth2\Storage\IClient;
use OAuth2\Storage\IScope;
use OAuth2\Storage\IUser;
use PhpSpec\ObjectBehavior;
use Prophecy\Argument;

class ClientCredentialsSpec extends ObjectBehavior
{

    function let(
        IClientAuthenticator $clientAuthenticator,
        IAccessTokenStorage $accessTokenStorage,
        IScopeResolver $scopeResolver
    ) {
        $this->beConstructedWith($clientAuthenticator, $accessTokenStorage, $scopeResolver);
    }

    function it_is_initializable()
    {
        $this->shouldHaveType('OAuth2\GrantType\ClientCredentials');
        $this->shouldImplement('OAuth2\GrantType\IGrantType');
    }


    function it_matches_against_request(
        IRequest $request1,
        IRequest $request2
    ) {
        $request1->request('grant_type')->willReturn('client_credentials')->shouldBeCalled();
        $this->match($request1)->shouldReturn(true);

        $request2->request('grant_type')->willReturn('pom')->shouldBeCalled();
        $this->match($request2)->shouldReturn(false);
    }

    function it_throws_exception_if_client_is_not_allowed_to_use_this_grant_type(
        IRequest $request,
        IClient $client,
        IClientAuthenticator $clientAuthenticator
    ) {
        $clientAuthenticator->authenticate($request)->willReturn($client)->shouldBeCalled();
        $client->isAllowedToUse($this)->willReturn(false)->shouldBeCalled();
        $this->shouldThrow(new UnauthorizedClientException('Client can not use this grant type.'))->during('grant', [$request]);
    }

    function it_throws_exception_if_client_is_public(
        IRequest $request,
        IClientAuthenticator $clientAuthenticator,
        IClient $client
    ) {
        $clientAuthenticator->authenticate($request)->willReturn($client)->shouldBeCalled();
        $client->isAllowedToUse($this)->willReturn(true)->shouldBeCalled();
        $client->getSecret()->willReturn(null)->shouldBeCalled();

        $this
            ->shouldThrow(new InvalidClientException('Only confidential clients can use this method.'))
            ->during('grant', [$request]);
    }

    function it_throws_exception_if_client_and_default_scopes_are_not_set(
        IRequest $request,
        IClientAuthenticator $clientAuthenticator,
        IClient $client,
        IScopeResolver $scopeResolver
    ) {
        $clientAuthenticator->authenticate($request)->willReturn($client)->shouldBeCalled();
        $client->isAllowedToUse($this)->willReturn(true)->shouldBeCalled();
        $client->getSecret()->willReturn('secret')->shouldBeCalled();
        $request->request('scope')->willReturn(null)->shouldBeCalled();
        $client->getScopes()->willReturn([])->shouldBeCalled();
        $scopeResolver->getDefaultScopes()->willReturn([])->shouldBeCalled();

        $this
            ->shouldThrow(new InvalidScopeException('Scope parameter has to be specified.'))
            ->during('grant', [$request]);
    }

    function it_issues_an_access_token_using_client_scopes(
        IRequest $request,
        IClientAuthenticator $clientAuthenticator,
        IClient $client,
        IAccessTokenStorage $accessTokenStorage,
        IAccessToken $accessToken,
        IScopeResolver $scopeResolver,
        IScope $scope
    ) {
        $clientAuthenticator->authenticate($request)->willReturn($client)->shouldBeCalled();
        $client->isAllowedToUse($this)->willReturn(true)->shouldBeCalled();
        $client->getSecret()->willReturn('secret')->shouldBeCalled();
        $request->request('scope')->willReturn(null)->shouldBeCalled();
        $client->getScopes()->willReturn([$scope])->shouldBeCalled();
        $scopeResolver->getDefaultScopes()->shouldNotBeCalled();
        $scopeResolver->intersect(null, [$scope])->willReturn([$scope])->shouldBeCalled();
        $client->getOwner()->willReturn(null)->shouldBeCalled();
        $accessTokenStorage->generate(null, $client, [$scope])->willReturn($accessToken)->shouldBeCalled();

        $this->grant($request)->shouldReturn($accessToken);
    }


    function it_issues_an_access_token_using_default_scopes(
        IRequest $request,
        IClientAuthenticator $clientAuthenticator,
        IClient $client,
        IAccessTokenStorage $accessTokenStorage,
        IAccessToken $accessToken,
        IScopeResolver $scopeResolver,
        IScope $scope,
        IUser $user
    ) {
        $clientAuthenticator->authenticate($request)->willReturn($client)->shouldBeCalled();
        $client->isAllowedToUse($this)->willReturn(true)->shouldBeCalled();
        $client->getSecret()->willReturn('secret')->shouldBeCalled();
        $request->request('scope')->willReturn(null)->shouldBeCalled();
        $client->getScopes()->willReturn([])->shouldBeCalled();
        $scopeResolver->getDefaultScopes()->willReturn([$scope])->shouldBeCalled();
        $scopeResolver->intersect(null, [$scope])->willReturn([$scope])->shouldBeCalled();
        $client->getOwner()->willReturn($user)->shouldBeCalled();
        $accessTokenStorage->generate($user, $client, [$scope])->willReturn($accessToken)->shouldBeCalled();

        $this->grant($request)->shouldReturn($accessToken);
    }

}
