<?php

namespace spec\OAuth2\Security\ClientAuthenticationMethod;

use OAuth2\Exception\InvalidClientException;
use OAuth2\Http\IRequest;
use OAuth2\Storage\IClient;
use OAuth2\Storage\IClientStorage;
use PhpSpec\ObjectBehavior;
use Prophecy\Argument;

class RequestBodySpec extends ObjectBehavior
{

    function let(IClientStorage $clientStorage)
    {
        $this->beConstructedWith($clientStorage);
    }


    function it_is_initializable()
    {
        $this->shouldHaveType('OAuth2\Security\ClientAuthenticationMethod\RequestBody');
        $this->shouldImplement('OAuth2\Security\ClientAuthenticationMethod\IClientAuthenticationMethod');
    }


    function it_matches_to_requests_without_authorization_header(
        IRequest $request1,
        IRequest $request2
    ) {
        $request1->headers('authorization')->willReturn(null)->shouldBeCalled();
        $this->match($request1)->shouldReturn(true);

        $request2->headers('authorization')->willReturn('b')->shouldBeCalled();
        $this->match($request2)->shouldReturn(false);
    }


    function it_returns_authenticated_public_client(
        IRequest $request,
        IClientStorage $clientStorage,
        IClient $client
    ) {
        $request->request('client_id')->willReturn('public')->shouldBeCalled();
        $request->request('client_secret')->willReturn(null)->shouldBeCalled();
        $clientStorage->get('public')->willReturn($client)->shouldBeCalled();
        $client->getSecret()->willReturn(null)->shouldBeCalled();

        $this->authenticate($request)->shouldReturn($client);
    }


    function it_returns_authenticated_confidential_client(
        IRequest $request,
        IClientStorage $clientStorage,
        IClient $client
    ) {
        $request->request('client_id')->willReturn('public')->shouldBeCalled();
        $request->request('client_secret')->willReturn('secret')->shouldBeCalled();
        $clientStorage->get('public')->willReturn($client)->shouldBeCalled();
        $client->getSecret()->willReturn('secret')->shouldBeCalled();

        $this->authenticate($request)->shouldReturn($client);
    }


    function it_throws_exception_if_client_id_is_missing(
        IRequest $request
    ) {
        $request->request('client_id')->willReturn(null)->shouldBeCalled();
        $request->request('client_secret')->willReturn(null)->shouldBeCalled();

        $this
            ->shouldThrow(new InvalidClientException('Client id is missing.'))
            ->during('authenticate', [$request]);
    }

    function it_throws_exception_if_client_does_not_exist(
        IRequest $request,
        IClientStorage $clientStorage
    ) {
        $request->request('client_id')->willReturn('public')->shouldBeCalled();
        $request->request('client_secret')->willReturn(null)->shouldBeCalled();
        $clientStorage->get('public')->willReturn(null)->shouldBeCalled();

        $this
            ->shouldThrow(new InvalidClientException('Invalid client credentials.'))
            ->during('authenticate', [$request]);
    }

    function it_throw_exception_if_client_secret_is_missing_for_confidential_client(
        IRequest $request,
        IClientStorage $clientStorage,
        IClient $client
    ) {
        $request->request('client_id')->willReturn('confidential')->shouldBeCalled();
        $request->request('client_secret')->willReturn(null)->shouldBeCalled();
        $clientStorage->get('confidential')->willReturn($client)->shouldBeCalled();
        $client->getSecret()->willReturn('secret')->shouldBeCalled();

        $this
            ->shouldThrow(new InvalidClientException('Invalid client credentials.'))
            ->during('authenticate', [$request]);
    }

    function it_throws_exception_if_client_secret_is_provided_for_public_client(
        IRequest $request,
        IClientStorage $clientStorage,
        IClient $client
    ) {
        $request->request('client_id')->willReturn('public')->shouldBeCalled();
        $request->request('client_secret')->willReturn('secret')->shouldBeCalled();
        $clientStorage->get('public')->willReturn($client)->shouldBeCalled();
        $client->getSecret()->willReturn(null)->shouldBeCalled();

        $this
            ->shouldThrow(new InvalidClientException('Invalid client credentials.'))
            ->during('authenticate', [$request]);
    }

}
