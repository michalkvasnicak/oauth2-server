<?php

namespace spec\OAuth2\Security\ClientAuthenticationMethod;

use OAuth2\Exception\InvalidClientException;
use OAuth2\Http\IRequest;
use OAuth2\Storage\IClient;
use OAuth2\Storage\IClientStorage;
use PhpSpec\ObjectBehavior;
use Prophecy\Argument;

class HttpBasicSpec extends ObjectBehavior
{

    function let(IClientStorage $clientStorage)
    {
        $this->beConstructedWith($clientStorage);
    }

    function it_is_initializable()
    {
        $this->shouldHaveType('OAuth2\Security\ClientAuthenticationMethod\HttpBasic');
        $this->shouldImplement('OAuth2\Security\ClientAuthenticationMethod\IClientAuthenticationMethod');
    }


    function it_matches_only_on_http_basic_authorization_requests(
        IRequest $request1,
        IRequest $request2
    ) {
        $request1->headers('authorization', '')->willReturn('Basic')->shouldBeCalled();
        $this->match($request1)->shouldReturn(true);

        $request2->headers('authorization', '')->willReturn('Digest')->shouldBeCalled();
        $this->match($request2)->shouldReturn(false);
    }


    function it_returns_authenticated_public_client(
        IRequest $request,
        IClientStorage $clientStorage,
        IClient $client
    ) {
        $request->headers('PHP_AUTH_USER')->willReturn('test')->shouldBeCalled();
        $request->headers('PHP_AUTH_PW')->willReturn(null)->shouldBeCalled();
        $clientStorage->get('test')->willReturn($client)->shouldBeCalled();
        $client->getSecret()->willReturn(null)->shouldBeCalled();

        $this->authenticate($request)->shouldReturn($client);
    }


    function it_returns_authenticated_confidential_client(
        IRequest $request,
        IClientStorage $clientStorage,
        IClient $client
    ) {
        $request->headers('PHP_AUTH_USER')->willReturn('test')->shouldBeCalled();
        $request->headers('PHP_AUTH_PW')->willReturn('pw')->shouldBeCalled();
        $clientStorage->get('test')->willReturn($client)->shouldBeCalled();
        $client->getSecret()->willReturn('pw')->shouldBeCalled();

        $this->authenticate($request)->shouldReturn($client);
    }


    function it_throws_exception_if_client_id_is_missing(
        IRequest $request
    ) {
        $request->headers('PHP_AUTH_USER')->willReturn(null)->shouldBeCalled();
        $request->headers('PHP_AUTH_PW')->willReturn(null)->shouldBeCalled();

        $this
            ->shouldThrow(new InvalidClientException('Client id is missing.'))
            ->during('authenticate', [$request]);
    }

    function it_throws_exception_if_client_does_not_exist(
        IRequest $request,
        IClientStorage $clientStorage
    ) {
        $request->headers('PHP_AUTH_USER')->willReturn('test')->shouldBeCalled();
        $request->headers('PHP_AUTH_PW')->willReturn(null)->shouldBeCalled();
        $clientStorage->get('test')->willReturn(null)->shouldBeCalled();

        $this
            ->shouldThrow(new InvalidClientException('Invalid client credentials.'))
            ->during('authenticate', [$request]);
    }


    function it_throws_exception_if_client_secret_is_missing_for_confidential_client(
        IRequest $request,
        IClientStorage $clientStorage,
        IClient $client
    ) {
        $request->headers('PHP_AUTH_USER')->willReturn('confidential')->shouldBeCalled();
        $request->headers('PHP_AUTH_PW')->willReturn(null)->shouldBeCalled();
        $clientStorage->get('confidential')->willReturn($client)->shouldBeCalled();
        $client->getSecret()->willReturn('pw')->shouldBeCalled();

        $this
            ->shouldThrow(new InvalidClientException('Invalid client credentials.'))
            ->during('authenticate', [$request]);
    }


    function it_throws_exception_if_client_is_public_and_secret_was_provided(
        IRequest $request,
        IClientStorage $clientStorage,
        IClient $client
    ) {
        $request->headers('PHP_AUTH_USER')->willReturn('public')->shouldBeCalled();
        $request->headers('PHP_AUTH_PW')->willReturn('secret')->shouldBeCalled();
        $clientStorage->get('public')->willReturn($client)->shouldBeCalled();
        $client->getSecret()->willReturn(null)->shouldBeCalled();

        $this
            ->shouldThrow(new InvalidClientException('Invalid client credentials.'))
            ->during('authenticate', [$request]);
    }

}
