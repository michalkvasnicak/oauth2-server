<?php

namespace tests\OAuth2;

use OAuth2\GrantType\RefreshToken;
use tests\OAuth2\Fixtures\Client;
use tests\OAuth2\Fixtures\RefreshToken as OAuthRefreshToken;
use tests\OAuth2\Fixtures\Request;
use tests\OAuth2\Fixtures\Scope;
use tests\OAuth2\Fixtures\User;
use tests\OAuth2GrantTypeTest;

/**
 * @author Michal Kvasničák <michal.kvasnicak@mink.sk>
 */
class RefreshTokenGrantTypeExampleTest extends OAuth2GrantTypeTest
{

    protected function setUp()
    {
        parent::setUp();

        $refreshTokenGrantType = new RefreshToken(
            $this->getClientAuthenticator(),
            $this->getRefreshTokenStorage(),
            $this->getAccessTokenStorage(),
            $this->getScopeResolver()
        );

        $this->getClientStorage()->add(
            $publicClient = new Client('public', null, [$refreshTokenGrantType])
        );
        $this->getClientStorage()->add(
            $confidentialClient = new Client('confidential', 'secret', [$refreshTokenGrantType])
        );

        $this->getRefreshTokenStorage()->add(
            new OAuthRefreshToken('public', new User(), $publicClient, [new Scope('public')], time() + 60)
        );
        $this->getRefreshTokenStorage()->add(
            new OAuthRefreshToken('protected', new User(), $confidentialClient, [new Scope('confidential')], time() + 60)
        );

        $this->getGrantTypeResolver()->accept($refreshTokenGrantType);
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
                    'grant_type' => 'refresh_token',
                    'refresh_token' => 'public',
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
                    'grant_type' => 'refresh_token',
                    'refresh_token' => 'protected',
                    'scope' => 'confidential'
                ]
            ],
            [
                'headers' => [],
                'request' => [
                    'grant_type' => 'refresh_token',
                    'refresh_token' => 'public',
                    'client_id' => 'public'
                ]
            ],
            [
                'headers' => [],
                'request' => [
                    'grant_type' => 'refresh_token',
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
     * @expectedException \OAuth2\Exception\InvalidScopeException
     * @expectedExceptionMessage Scope 'unknown' is invalid.
     */
    public function test_throws_exception_on_invalid_requested_scope()
    {
        $request = new Request(
            'POST',
            ['authorization' => 'Basic', 'PHP_AUTH_USER' => 'public'],
            ['grant_type' => 'refresh_token', 'refresh_token' => 'public', 'scope' => 'unknown']
        );
        $this->getAccessTokenIssuer()->issueToken($request);
    }

}
 