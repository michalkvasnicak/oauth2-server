<?php

namespace tests\OAuth2;

use OAuth2\GrantType\ClientCredentials;
use OAuth2\TokenIssuer\AccessTokenIssuer;
use tests\OAuth2\Fixtures\Client;
use tests\OAuth2\Fixtures\Request;
use tests\OAuth2\Fixtures\Scope;
use tests\OAuth2GrantTypeTestCase;

/**
 * @author Michal Kvasničák <michal.kvasnicak@mink.sk>
 */
class ClientCredentialsGrantTypeTest extends OAuth2GrantTypeTestCase
{

    /** @var  AccessTokenIssuer  */
    protected $accessTokenIssuer;


    protected function setUp()
    {
        parent::setUp();

        $clientCredentialsGrantType = new ClientCredentials(
            $this->getClientAuthenticator(),
            $this->getAccessTokenStorage(),
            $this->getScopeResolver()
        );

        $this->getClientStorage()->add(
            new Client('public', null, [$clientCredentialsGrantType], [new Scope('public')])
        );
        $this->getClientStorage()->add(
            new Client('confidential', 'secret', [$clientCredentialsGrantType], [new Scope('confidential')])
        );

        $this->getGrantTypeResolver()->accept($clientCredentialsGrantType);
    }


    public function test_issue_access_token_using_confidential_client_authentication_methods()
    {
        $clients = [
            [
                'headers' => [
                    'authorization' => 'Basic',
                    'PHP_AUTH_USER' => 'confidential',
                    'PHP_AUTH_PW' => 'secret'
                ],
                'request' => [
                    'grant_type' => 'client_credentials',
                    'scope' => 'confidential'
                ]
            ],
            [
                'headers' => [],
                'request' => [
                    'grant_type' => 'client_credentials',
                    'refresh_token' => 'protected',
                    'client_id' => 'confidential',
                    'client_secret' => 'secret'
                ]
            ]
        ];

        foreach ($clients as $client) {
            $request = new Request(
                'POST',
                $client['headers'],
                $client['request']
            );
            $token = $this->getAccessTokenIssuer()->issueToken($request);

            $this->assertInstanceOf('OAuth2\Storage\IAccessToken', $token);
            $this->assertGreaterThan(time(), $token->getExpiresAt());
            $this->assertNotEmpty($token->getScopes());
            $this->assertEquals(
                isset($client['headers']['PHP_AUTH_USER']) ? $client['headers']['PHP_AUTH_USER'] : $client['request']['client_id'],
                $token->getClient()->getId()
            );
        }
    }

    /**
     * @expectedException OAuth2\Exception\InvalidScopeException
     * @expectedExceptionMessage Scope 'unknown' is invalid.
     */
    public function test_throws_exception_on_invalid_requested_scope()
    {
        $request = new Request(
            'POST',
            ['authorization' => 'Basic', 'PHP_AUTH_USER' => 'confidential', 'PHP_AUTH_PW' => 'secret'],
            ['grant_type' => 'client_credentials', 'scope' => 'unknown']
        );
        $this->getAccessTokenIssuer()->issueToken($request);
    }

    /**
     * @expectedException OAuth2\Exception\InvalidClientException
     * @expectedExceptionMessage Only confidential clients can use this method.
     */
    public function test_throws_exception_on_public_client_request()
    {
        $request = new Request(
            'POST',
            ['authorization' => 'Basic', 'PHP_AUTH_USER' => 'public'],
            ['grant_type' => 'client_credentials', 'scope' => 'unknown']
        );
        $this->getAccessTokenIssuer()->issueToken($request);
    }

}
 