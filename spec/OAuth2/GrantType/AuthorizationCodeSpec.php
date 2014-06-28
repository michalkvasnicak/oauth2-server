<?php

namespace spec\OAuth2\GrantType;

use OAuth2\Exception\InvalidClientException;
use OAuth2\Exception\InvalidGrantException;
use OAuth2\Exception\InvalidRequestException;
use OAuth2\Exception\InvalidScopeException;
use OAuth2\Exception\UnauthorizedClientException;
use OAuth2\Http\IRequest;
use OAuth2\Resolver\IScopeResolver;
use OAuth2\Security\IClientAuthenticator;
use OAuth2\Storage\IAccessToken;
use OAuth2\Storage\IAccessTokenStorage;
use OAuth2\Storage\IAuthorizationCode;
use OAuth2\Storage\IAuthorizationCodeStorage;
use OAuth2\Storage\IClient;
use OAuth2\Storage\IClientStorage;
use OAuth2\Storage\IScope;
use OAuth2\Storage\IUser;
use PhpSpec\ObjectBehavior;
use Prophecy\Argument;

class AuthorizationCodeSpec extends ObjectBehavior
{

    function let(
        IClientAuthenticator $clientAuthenticator,
        IClientStorage $clientStorage,
        IAuthorizationCodeStorage $authorizationCodeStorage,
        IAccessTokenStorage $accessTokenStorage,
        IScopeResolver $scopeResolver
    ) {
        $this->beConstructedWith($clientAuthenticator, $clientStorage, $authorizationCodeStorage, $accessTokenStorage, $scopeResolver);
    }


    function it_is_initializable()
    {
        $this->shouldHaveType('OAuth2\GrantType\AuthorizationCode');
        $this->shouldImplement('OAuth2\GrantType\IAuthorizationGrantType');
    }


    function it_matches_against_request(
        IRequest $request1,
        IRequest $request2,
        IRequest $request3,
        IRequest $request4
    )
    {
        $request1->isMethod('GET')->willReturn(true)->shouldBeCalled();
        $request1->query('response_type')->willReturn('code')->shouldBeCalled();

        $this->match($request1)->shouldReturn(true);

        $request2->isMethod('GET')->willReturn(false)->shouldBeCalled();
        $request2->request('grant_type')->willReturn('authorization_code')->shouldBeCalled();

        $this->match($request2)->shouldReturn(true);

        $request3->isMethod('GET')->willReturn(true)->shouldBeCalled();
        $request3->query('response_type')->willReturn('pom')->shouldBeCalled();

        $this->match($request3)->shouldReturn(false);

        $request4->isMethod('GET')->willReturn(false)->shouldBeCalled();
        $request4->request('grant_type')->willReturn('pom')->shouldBeCalled();

        $this->match($request4)->shouldReturn(false);
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
        $request->query('redirect_uri')->willReturn('http://pom-dev.sk#pompom')->shouldBeCalled();
        $clientStorage->get('a')->willReturn($client)->shouldBeCalled();
        $client->isAllowedToUse($this)->willReturn(true)->shouldBeCalled();
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
        $request->query('redirect_uri')->willReturn('http://pom-dev.sk')->shouldBeCalled();
        $clientStorage->get('a')->willReturn($client)->shouldBeCalled();
        $client->isAllowedToUse($this)->willReturn(true)->shouldBeCalled();
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
        $request->query('redirect_uri')->willReturn(null)->shouldBeCalled();
        $clientStorage->get('a')->willReturn($client)->shouldBeCalled();
        $client->isAllowedToUse($this)->willReturn(true)->shouldBeCalled();
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
        $request->query('redirect_uri')->willReturn(null)->shouldBeCalled();
        $clientStorage->get('a')->willReturn($client)->shouldBeCalled();
        $client->isAllowedToUse($this)->willReturn(true)->shouldBeCalled();
        $client->getRedirectUri()->willReturn('http://google.sk')->shouldBeCalled();
        $request->query('scope')->willReturn(null)->shouldBeCalled();
        $client->getScopes()->willReturn([])->shouldBeCalled();
        $scopeResolver->getDefaultScopes()->willReturn([])->shouldBeCalled();

        $this
            ->shouldThrow(new InvalidScopeException('Scope parameter has to be specified.'))
            ->during('authorize', [$request, $user]);
    }


    function it_issues_authorization_code_and_creates_authorization_session(
        IRequest $request,
        IClientStorage $clientStorage,
        IClient $client,
        IAuthorizationCodeStorage $authorizationCodeStorage,
        IAuthorizationCode $authorizationCode,
        IScopeResolver $scopeResolver,
        IScope $scope,
        IUser $user
    ) {
        $request->query('client_id')->willReturn('a')->shouldBeCalled();
        $request->query('redirect_uri')->willReturn(null)->shouldBeCalled();
        $clientStorage->get('a')->willReturn($client)->shouldBeCalled();
        $client->isAllowedToUse($this)->willReturn(true)->shouldBeCalled();
        $client->getRedirectUri()->willReturn('http://google.sk')->shouldBeCalled();
        $request->query('state')->willReturn('test')->shouldBeCalled();
        $request->query('scope')->willReturn(null)->shouldBeCalled();
        $client->getScopes()->willReturn([$scope])->shouldBeCalled();
        $scopeResolver->intersect(null, [$scope])->willReturn([$scope])->shouldBeCalled();
        $authorizationCodeStorage
            ->generate($user, $client, [$scope], 'http://google.sk', 'test')
            ->willReturn($authorizationCode)
            ->shouldBeCalled();

        $this->authorize($request, $user)->shouldReturnAnInstanceOf('OAuth2\Security\AuthorizationCodeSession');
    }


    function it_throws_exception_if_grant_request_does_not_contain_code(
        IRequest $request
    ) {
        $request->request('code')->willReturn(null)->shouldBeCalled();

        $this
            ->shouldThrow(new InvalidRequestException("Parameter 'code' is missing."))
            ->during('grant', [$request]);
    }


    function it_throws_exception_if_grant_request_contains_client_that_is_not_allowed_to_use_this_grant_type(
        IRequest $request,
        IClientAuthenticator $clientAuthenticator,
        IClient $client
    ) {
        $request->request('code')->willReturn('a')->shouldBeCalled();
        $clientAuthenticator->authenticate($request)->willReturn($client)->shouldBeCalled();
        $client->isAllowedToUse($this)->willReturn(false)->shouldBeCalled();

        $this
            ->shouldThrow(new UnauthorizedClientException('Client can not use this grant type.'))
            ->during('grant', [$request]);
    }


    function it_throws_exception_if_grant_request_contains_invalid_code(
        IRequest $request,
        IAuthorizationCodeStorage $authorizationCodeStorage,
        IClientAuthenticator $clientAuthenticator,
        IClient $client
    ) {
        $request->request('code')->willReturn('a')->shouldBeCalled();
        $clientAuthenticator->authenticate($request)->willReturn($client)->shouldBeCalled();
        $client->isAllowedToUse($this)->willReturn(true)->shouldBeCalled();
        $authorizationCodeStorage->get('a')->willReturn(null)->shouldBeCalled();

        $this
            ->shouldThrow(new InvalidGrantException('Authorization code is invalid.'))
            ->during('grant', [$request]);
    }


    function it_throws_exception_if_grant_request_contains_expired_code(
        IRequest $request,
        IAuthorizationCodeStorage $authorizationCodeStorage,
        IAuthorizationCode $authorizationCode,
        IClientAuthenticator $clientAuthenticator,
        IClient $client
    ) {
        $request->request('code')->willReturn('a')->shouldBeCalled();
        $clientAuthenticator->authenticate($request)->willReturn($client)->shouldBeCalled();
        $client->isAllowedToUse($this)->willReturn(true)->shouldBeCalled();
        $authorizationCodeStorage->get('a')->willReturn($authorizationCode)->shouldBeCalled();

        $authorizationCode->getExpiresAt()->willReturn(time() - 10)->shouldBeCalled();

        $this
            ->shouldThrow(new InvalidGrantException('Authorization code has expired.'))
            ->during('grant', [$request]);
    }


    function it_throws_exception_if_grant_request_authorization_code_was_issued_to_another_client(
        IRequest $request,
        IAuthorizationCodeStorage $authorizationCodeStorage,
        IAuthorizationCode $authorizationCode,
        IClientAuthenticator $clientAuthenticator,
        IClient $client1,
        IClient $client2
    ) {
        $request->request('code')->willReturn('a')->shouldBeCalled();
        $clientAuthenticator->authenticate($request)->willReturn($client1)->shouldBeCalled();
        $client1->isAllowedToUse($this)->willReturn(true)->shouldBeCalled();
        $authorizationCodeStorage->get('a')->willReturn($authorizationCode)->shouldBeCalled();
        $authorizationCode->getExpiresAt()->willReturn(time() + 100)->shouldBeCalled();
        $client1->getId()->willReturn('b')->shouldBeCalled();
        $client2->getId()->willReturn('c')->shouldBeCalled();
        $authorizationCode->getClient()->willReturn($client2)->shouldBeCalled();

        $this
            ->shouldThrow(new InvalidGrantException('Authorization code is invalid.'))
            ->during('grant', [$request]);
    }


    function it_throws_exception_if_grant_request_does_not_contain_redirect_uri_and_was_used_in_authorization(
        IRequest $request,
        IAuthorizationCodeStorage $authorizationCodeStorage,
        IAuthorizationCode $authorizationCode,
        IClientAuthenticator $clientAuthenticator,
        IClient $client
    ) {
        $request->request('code')->willReturn('a')->shouldBeCalled();
        $clientAuthenticator->authenticate($request)->willReturn($client)->shouldBeCalled();
        $client->isAllowedToUse($this)->willReturn(true)->shouldBeCalled();
        $authorizationCodeStorage->get('a')->willReturn($authorizationCode)->shouldBeCalled();
        $authorizationCode->getExpiresAt()->willReturn(time() + 100)->shouldBeCalled();
        $client->getId()->willReturn('id')->shouldBeCalled();
        $authorizationCode->getClient()->willReturn($client)->shouldBeCalled();
        $request->request('redirect_uri')->willReturn(null)->shouldBeCalled();
        $authorizationCode->getRedirectUri()->willReturn('http://pom.dev')->shouldBeCalled();

        $this
            ->shouldThrow(new InvalidRequestException('Redirect URI is missing, was not used in authorization or is invalid.'))
            ->during('grant', [$request]);
    }


    function it_throws_exception_if_grant_request_contain_redirect_uri_and_was_not_used_in_authorization(
        IRequest $request,
        IAuthorizationCodeStorage $authorizationCodeStorage,
        IAuthorizationCode $authorizationCode,
        IClientAuthenticator $clientAuthenticator,
        IClient $client
    ) {
        $request->request('code')->willReturn('a')->shouldBeCalled();
        $clientAuthenticator->authenticate($request)->willReturn($client)->shouldBeCalled();
        $client->isAllowedToUse($this)->willReturn(true)->shouldBeCalled();
        $authorizationCodeStorage->get('a')->willReturn($authorizationCode)->shouldBeCalled();
        $authorizationCode->getExpiresAt()->willReturn(time() + 100)->shouldBeCalled();
        $client->getId()->willReturn('id')->shouldBeCalled();
        $authorizationCode->getClient()->willReturn($client)->shouldBeCalled();
        $request->request('redirect_uri')->willReturn('http://pom.dev')->shouldBeCalled();
        $authorizationCode->getRedirectUri()->willReturn(null)->shouldBeCalled();

        $this
            ->shouldThrow(new InvalidRequestException('Redirect URI is missing, was not used in authorization or is invalid.'))
            ->during('grant', [$request]);
    }


    function it_throws_exception_if_grant_request_contain_redirect_uris_does_not_match(
        IRequest $request,
        IAuthorizationCodeStorage $authorizationCodeStorage,
        IAuthorizationCode $authorizationCode,
        IClientAuthenticator $clientAuthenticator,
        IClient $client
    ) {
        $request->request('code')->willReturn('a')->shouldBeCalled();
        $clientAuthenticator->authenticate($request)->willReturn($client)->shouldBeCalled();
        $client->isAllowedToUse($this)->willReturn(true)->shouldBeCalled();
        $authorizationCodeStorage->get('a')->willReturn($authorizationCode)->shouldBeCalled();
        $authorizationCode->getExpiresAt()->willReturn(time() + 100)->shouldBeCalled();
        $client->getId()->willReturn('id')->shouldBeCalled();
        $authorizationCode->getClient()->willReturn($client)->shouldBeCalled();
        $request->request('redirect_uri')->willReturn('http://pom.dev')->shouldBeCalled();
        $authorizationCode->getRedirectUri()->willReturn('http://pom1.dev')->shouldBeCalled();

        $this
            ->shouldThrow(new InvalidRequestException('Redirect URI is missing, was not used in authorization or is invalid.'))
            ->during('grant', [$request]);
    }


    function it_issues_an_access_token(
        IRequest $request,
        IClientAuthenticator $clientAuthenticator,
        IAuthorizationCodeStorage $authorizationCodeStorage,
        IAuthorizationCode $authorizationCode,
        IAccessTokenStorage $accessTokenStorage,
        IAccessToken $accessToken,
        IUser $user,
        IClient $client,
        IScope $scope
    ) {
        $request->request('code')->willReturn('a')->shouldBeCalled();
        $clientAuthenticator->authenticate($request)->willReturn($client)->shouldBeCalled();
        $client->isAllowedToUse($this)->willReturn(true)->shouldBeCalled();
        $authorizationCodeStorage->get('a')->willReturn($authorizationCode)->shouldBeCalled();
        $authorizationCode->getExpiresAt()->willReturn(time() + 100)->shouldBeCalled();
        $client->getId()->willReturn('id')->shouldBeCalled();
        $authorizationCode->getClient()->willReturn($client)->shouldBeCalled();
        $request->request('redirect_uri')->willReturn(null)->shouldBeCalled();
        $authorizationCode->getRedirectUri()->willReturn(null)->shouldBeCalled();
        $authorizationCode->getScopes()->willReturn([$scope])->shouldBeCalled();
        $authorizationCode->getUser()->willReturn($user)->shouldBeCalled();
        $authorizationCode->getClient()->willReturn($client)->shouldBeCalled();

        $accessTokenStorage->generate($user, $client, [$scope])->willReturn($accessToken)->shouldBeCalled();

        $this->grant($request)->shouldReturn($accessToken);
    }

}
