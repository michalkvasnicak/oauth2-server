<?php

namespace tests\OAuth2;

use OAuth2\GrantType\ResourceOwnerPasswordCredentials;
use tests\OAuth2\Fixtures\Client;
use tests\OAuth2\Fixtures\Request;
use tests\OAuth2\Fixtures\Scope;
use tests\OAuth2\Fixtures\User;
use tests\OAuth2GrantTypeTest;

/**
 * @author Michal Kvasničák <michal.kvasnicak@mink.sk>
 */
class ResourceOwnerPasswordCredentialsGrantTypeTest extends OAuth2GrantTypeTest
{

    protected function setUp()
    {
        parent::setUp();

        $admin = new User('admin', 'root');
        $user = new User('user', 'user');

        $this->getUserAuthenticator()->addUser($admin);
        $this->getUserAuthenticator()->addUser($user);

        $resourceOwnerPasswordCredentialsGrantType = new ResourceOwnerPasswordCredentials(
            $this->getClientAuthenticator(),
            $this->getUserAuthenticator(),
            $this->getAccessTokenStorage(),
            $this->getScopeResolver()
        );

        $this->getClientStorage()->add(
            new Client('public', null, [$resourceOwnerPasswordCredentialsGrantType], [new Scope('public')])
        );
        $this->getClientStorage()->add(
            new Client('confidential', 'secret', [$resourceOwnerPasswordCredentialsGrantType], [new Scope('confidential')])
        );

        $this->getGrantTypeResolver()->accept($resourceOwnerPasswordCredentialsGrantType);
    }


    public function test_issue_access_token_using_various_client_authentication_methods()
    {
        $clients = [
            [
                'headers' => [
                    'authorization' => 'Basic',
                    'PHP_AUTH_USER' => 'public'
                ],
                'request' => [
                    'grant_type' => 'password',
                    'username' => 'admin',
                    'password' => 'root',
                    'scope' => 'public'
                ]
            ],
            [
                'headers' => [
                    'authorization' => 'Basic',
                    'PHP_AUTH_USER' => 'confidential',
                    'PHP_AUTH_PW' => 'secret'
                ],
                'request' => [
                    'grant_type' => 'password',
                    'username' => 'user',
                    'password' => 'user'
                ]
            ],
            [
                'headers' => [],
                'request' => [
                    'client_id' => 'public',
                    'grant_type' => 'password',
                    'username' => 'user',
                    'password' => 'user'
                ]
            ],
            [
                'headers' => [],
                'request' => [
                    'client_id' => 'confidential',
                    'client_secret' => 'secret',
                    'grant_type' => 'password',
                    'username' => 'admin',
                    'password' => 'root'
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
     * @expectedException \OAuth2\Exception\InvalidScopeException
     * @expectedExceptionMessage Scope 'unknown' is invalid.
     */
    public function test_throws_exception_on_invalid_requested_scope()
    {
        $request = new Request(
            'POST',
            ['authorization' => 'Basic', 'PHP_AUTH_USER' => 'public'],
            ['grant_type' => 'password', 'username' => 'admin', 'password' => 'root', 'scope' => 'unknown']
        );
        $this->getAccessTokenIssuer()->issueToken($request);
    }


}
 