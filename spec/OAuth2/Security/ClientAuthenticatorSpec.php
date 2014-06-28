<?php

namespace spec\OAuth2\Security;

use OAuth2\Exception\InvalidClientException;
use OAuth2\Http\IRequest;
use OAuth2\Security\ClientAuthenticationMethod\IClientAuthenticationMethod;
use OAuth2\Storage\IClient;
use PhpSpec\ObjectBehavior;
use Prophecy\Argument;

class ClientAuthenticatorSpec extends ObjectBehavior
{
    function it_is_initializable()
    {
        $this->shouldHaveType('OAuth2\Security\ClientAuthenticator');
        $this->shouldImplement('OAuth2\Security\IClientAuthenticator');
    }


    function it_returns_client_on_successful_client_authentication(
        IRequest $request,
        IClientAuthenticationMethod $clientAuthenticatorMethod,
        IClient $client
    ) {
        $this->accept($clientAuthenticatorMethod);
        $clientAuthenticatorMethod->match($request)->willReturn(true)->shouldBeCalled();
        $clientAuthenticatorMethod->authenticate($request)->willReturn($client)->shouldBeCalled();
        $this->authenticate($request)->shouldReturn($client);
    }


    function it_throws_exception_if_requested_authentication_method_is_not_accepted(
        IRequest $request,
        IClientAuthenticationMethod $clientAuthenticationMethod
    ) {
        $this->accept($clientAuthenticationMethod);
        $clientAuthenticationMethod->match($request)->willReturn(false)->shouldBeCalled();
        $clientAuthenticationMethod->authenticate($request)->shouldNotBeCalled();
        $this
            ->shouldThrow(new InvalidClientException('Invalid client authentication method.'))
            ->during('authenticate', [$request]);
    }

}
