<?php

namespace spec\OAuth2\GrantType;

use OAuth2\Exception\InvalidClientException;
use OAuth2\Exception\InvalidRequestException;
use OAuth2\Exception\InvalidScopeException;
use OAuth2\Exception\UnauthorizedClientException;
use OAuth2\Http\IRequest;
use OAuth2\Resolver\IScopeResolver;
use OAuth2\Storage\IAccessToken;
use OAuth2\Storage\IAccessTokenStorage;
use OAuth2\Storage\IClient;
use OAuth2\Storage\IClientStorage;
use OAuth2\Storage\IScope;
use OAuth2\Storage\IUser;
use OAuth2\TokenType\ITokenType;
use PhpSpec\ObjectBehavior;
use Prophecy\Argument;

class ImplicitSpec extends ObjectBehavior
{

    function let(
        IClientStorage $clientStorage,
        IAccessTokenStorage $accessTokenStorage,
        IScopeResolver $scopeResolver,
        ITokenType $tokenType
    ) {
        $this->beConstructedWith($clientStorage, $accessTokenStorage, $scopeResolver, $tokenType);
    }


    function it_is_initializable()
    {
        $this->shouldHaveType('OAuth2\GrantType\Implicit');
        $this->shouldImplement('OAuth2\GrantType\IAuthorizationGrantType');
    }


    function it_throws_exception_if_grant_method_is_called(
        IRequest $request
    ) {
        $this
            ->shouldThrow(new \RuntimeException('Implicit grant type can not be used in token endpoint.'))
            ->during('grant', [$request]);
    }


    function it_matches_against_request(
        IRequest $request1,
        IRequest $request2,
        IRequest $request3
    ) {
        $request1->isMethod('GET')->willReturn(true)->shouldBeCalled();
        $request1->query('response_type')->willReturn('token')->shouldBeCalled();
        $this->match($request1)->shouldReturn(true);

        $request2->isMethod('GET')->willReturn(false)->shouldBeCalled();
        $this->match($request2)->shouldReturn(false);

        $request3->isMethod('GET')->willReturn(true)->shouldBeCalled();
        $request3->query('response_type')->willReturn(null)->shouldBeCalled();
        $this->match($request3)->shouldReturn(false);
    }


    function it_throws_exception_if_authorization_request_does_not_contain_client_id(
        IRequest $request,
        IUser $user
    ) {
        $request->query('client_id')->willReturn(null)->shouldBeCalled();

        $this
            ->shouldThrow(new InvalidRequestException('Client id is missing.'))
            ->during('authorize', [$request, $user]);
    }

    function it_throws_exception_if_authorization_request_contains_client_that_does_not_exist(
        IRequest $request,
        IClientStorage $clientStorage,
        IUser $user
    ) {
        $request->query('client_id')->willReturn('a')->shouldBeCalled();
        $clientStorage->get('a')->willReturn(null)->shouldBeCalled();

        $this
            ->shouldThrow(new InvalidClientException('Invalid client.'))
            ->during('authorize', [$request, $user]);
    }

    function it_throws_exception_if_authorization_request_contains_client_that_is_not_allowed_to_use_this_grant_type(
        IRequest $request,
        IClientStorage $clientStorage,
        IClient $client,
        IUser $user
    ) {
        $request->query('client_id')->willReturn('a')->shouldBeCalled();
        $clientStorage->get('a')->willReturn($client)->shouldBeCalled();
        $client->isAllowedToUse($this)->willReturn(false)->shouldBeCalled();

        $this
            ->shouldThrow(new UnauthorizedClientException('Client can not use this grant type.'))
            ->during('authorize', [$request, $user]);
    }

    function it_throws_exception_if_authorization_request_contains_invalid_redirect_uri(
        IRequest $request,
        IClientStorage $clientStorage,
        IClient $client,
        IUser $user
    ) {
        $request->query('client_id')->willReturn('a')->shouldBeCalled();
        $clientStorage->get('a')->willReturn($client)->shouldBeCalled();
        $client->isAllowedToUse($this)->willReturn(true)->shouldBeCalled();
        $request->query('redirect_uri')->willReturn('http://pom-dev.sk#pompom')->shouldBeCalled();
        $client->getRedirectUri()->willReturn('http://google.com')->shouldBeCalled();

        $this
            ->shouldThrow(new InvalidRequestException('Redirect URI is invalid.'))
            ->during('authorize', [$request, $user]);
    }

    function it_throws_exception_if_authorization_request_contains_not_matching_redirect_uri(
        IRequest $request,
        IClientStorage $clientStorage,
        IClient $client,
        IUser $user
    ) {
        $request->query('client_id')->willReturn('a')->shouldBeCalled();
        $clientStorage->get('a')->willReturn($client)->shouldBeCalled();
        $client->isAllowedToUse($this)->willReturn(true)->shouldBeCalled();
        $request->query('redirect_uri')->willReturn('http://pom-dev.sk')->shouldBeCalled();
        $client->getRedirectUri()->willReturn('http://google.com')->shouldBeCalled();

        $this
            ->shouldThrow(new InvalidRequestException('Redirect URI does not match.'))
            ->during('authorize', [$request, $user]);
    }


    function it_throws_exception_if_authorization_request_does_not_contain_redirect_uri_and_client_too(
        IRequest $request,
        IClientStorage $clientStorage,
        IClient $client,
        IUser $user
    ) {
        $request->query('client_id')->willReturn('a')->shouldBeCalled();
        $clientStorage->get('a')->willReturn($client)->shouldBeCalled();
        $client->isAllowedToUse($this)->willReturn(true)->shouldBeCalled();
        $request->query('redirect_uri')->willReturn(null)->shouldBeCalled();
        $client->getRedirectUri()->willReturn(null)->shouldBeCalled();

        $this
            ->shouldThrow(new InvalidRequestException('Redirect URI was not supplied or registered.'))
            ->during('authorize', [$request, $user]);
    }


    function it_throws_exception_if_authorization_request_does_not_contain_scope_and_client_too(
        IRequest $request,
        IClientStorage $clientStorage,
        IClient $client,
        IScopeResolver $scopeResolver,
        IUser $user
    ) {
        $request->query('client_id')->willReturn('a')->shouldBeCalled();
        $clientStorage->get('a')->willReturn($client)->shouldBeCalled();
        $client->isAllowedToUse($this)->willReturn(true)->shouldBeCalled();
        $request->query('redirect_uri')->willReturn(null)->shouldBeCalled();
        $client->getRedirectUri()->willReturn('http://google.sk')->shouldBeCalled();
        $request->query('scope')->willReturn(null)->shouldBeCalled();
        $user->getScopes()->willReturn([])->shouldBeCalled();
        $scopeResolver->getDefaultScopes()->willReturn([])->shouldBeCalled();

        $this
            ->shouldThrow(new InvalidScopeException('Scope parameter has to be specified.'))
            ->during('authorize', [$request, $user]);
    }

    function it_should_issue_access_token_and_return_implicit_authorization_session(
        IAccessTokenStorage $accessTokenStorage,
        IScopeResolver $scopeResolver,
        IClientStorage $clientStorage,
        IClient $client,
        IRequest $request,
        ITokenType $tokenType,
        IUser $user,
        IAccessToken $accessToken,
        IScope $scope
    ) {
        $request->query('client_id')->willReturn('test')->shouldBeCalled();
        $clientStorage->get('test')->willReturn($client)->shouldBeCalled();
        $client->isAllowedToUse($this)->willReturn(true)->shouldBeCalled();
        $request->query('redirect_uri')->willReturn('http://google.com')->shouldBeCalled();
        $client->getRedirectUri()->willReturn('http://google.com')->shouldBeCalled();
        $request->query('scope')->willReturn('scope1')->shouldBeCalled();
        $user->getScopes()->willReturn([])->shouldBeCalled();
        $scopeResolver->getDefaultScopes()->willReturn([$scope])->shouldBeCalled();
        $scopeResolver->intersect('scope1', [$scope])->willReturn([$scope])->shouldBeCalled();
        $request->query('state')->willReturn(null)->shouldBeCalled();
        $accessTokenStorage->generate($user, $client, [$scope])->willReturn($accessToken)->shouldBeCalled();
        $tokenType->getName()->willReturn('Bearer')->shouldBeCalled();

        $this->authorize($request, $user)->shouldReturnAnInstanceOf('OAuth2\Security\ImplicitSession');
    }

}
