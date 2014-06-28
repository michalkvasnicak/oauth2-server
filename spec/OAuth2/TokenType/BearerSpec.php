<?php

namespace spec\OAuth2\TokenType;

use OAuth2\Http\IRequest;
use PhpSpec\ObjectBehavior;
use Prophecy\Argument;

class BearerSpec extends ObjectBehavior
{
    function it_is_initializable()
    {
        $this->shouldHaveType('OAuth2\TokenType\Bearer');
        $this->shouldImplement('OAuth2\TokenType\ITokenType');
    }


    function it_should_match_against_request_with_access_token_in_authorization_header(
        IRequest $request
    ) {
        $request->headers('authorization')->willReturn('Bearer pompom')->shouldBeCalled();
        $request->request('access_token')->shouldNotBeCalled();
        $request->query('access_token')->shouldNotBeCalled();
        $this->match($request)->shouldReturn(true);
    }


    function it_should_throw_exception_on_malformed_bearer_token(
        IRequest $request
    ) {
        $request->headers('authorization')->willReturn('Bearer')->shouldBeCalled();
        $this->shouldThrow('OAuth2\Exception\MalformedTokenException')->during('match', [$request]);
    }


    function it_should_match_against_request_with_access_token_in_body(
        IRequest $request
    ) {
        $request->headers('authorization')->willReturn(null)->shouldBeCalled();
        $request->request('access_token')->willReturn('pompompom')->shouldBeCalled();
        $request->headers('content_type')->willReturn('application/x-www-form-urlencoded');
        $request->query('access_token')->shouldNotBeCalled();
        $request->isMethod('post')->willReturn(true)->shouldBeCalled();
        $request->isMethod('put')->shouldNotBeCalled();
        $this->match($request)->shouldReturn(true);
    }


    function it_should_throw_exception_on_invalid_http_method_and_access_token_in_body(
        IRequest $request
    ) {
        $request->headers('authorization')->willReturn(null)->shouldBeCalled();
        $request->request('access_token')->willReturn('pompompom')->shouldBeCalled();
        $request->isMethod('post')->willReturn(false)->shouldBeCalled();
        $request->isMethod('put')->willReturn(false)->shouldBeCalled();
        $this->shouldThrow('OAuth2\Exception\InvalidHttpMethodException')->during('match', [$request]);
    }

    function it_should_throw_exception_on_invalid_content_type_and_access_token_in_body(
        IRequest $request
    ) {
        $request->headers('authorization')->willReturn(null)->shouldBeCalled();
        $request->request('access_token')->willReturn('pompompom')->shouldBeCalled();
        $request->isMethod('post')->willReturn(true)->shouldBeCalled();
        $request->headers('content_type')->willReturn('application/json')->shouldBeCalled();
        $this->shouldThrow('OAuth2\Exception\InvalidContentTypeException')->during('match', [$request]);
    }


    function it_should_match_against_request_with_access_token_in_url_query(
        IRequest $request
    ) {
        $request->headers('authorization')->willReturn(null)->shouldBeCalled();
        $request->request('access_token')->willReturn(null)->shouldBeCalled();
        $request->query('access_token')->willReturn('pompompom')->shouldBeCalled();
        $this->match($request)->shouldReturn(true);
    }


    function it_should_return_access_token_identifier_from_token_in_header(
        IRequest $request
    ) {
        $request->headers('authorization')->willReturn('Bearer pompompom');
        $this->match($request)->shouldReturn(true);
        $this->getAccessToken()->shouldReturn('pompompom');
    }


    function it_should_return_access_token_identifier_from_token_in_request_body(
        IRequest $request
    ) {
        $request->headers('authorization')->willReturn(null);
        $request->request('access_token')->willReturn('pom');
        $request->isMethod('post')->willReturn(true);
        $request->headers('content_type')->willReturn('application/x-www-form-urlencoded');
        $this->match($request)->shouldReturn(true);
        $this->getAccessToken()->shouldReturn('pom');
    }


    function it_should_return_access_token_from_token_in_uri_query_parameter(
        IRequest $request
    ) {
        $request->headers('authorization')->willReturn(null);
        $request->request('access_token')->willReturn(null);
        $request->query('access_token')->willReturn('pom');
        $this->match($request)->shouldReturn(true);
        $this->getAccessToken()->shouldReturn('pom');
    }

}
