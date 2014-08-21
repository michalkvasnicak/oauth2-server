<?php

namespace tests\OAuth2;

use OAuth2\GrantType\AuthorizationCode;
use tests\OAuth2\Fixtures\Client;
use tests\OAuth2\Fixtures\Request;
use tests\OAuth2\Fixtures\Scope;
use tests\OAuth2\Fixtures\User;
use tests\OAuth2GrantTypeTestCase;

/**
 * @author Michal Kvasničák <michal.kvasnicak@mink.sk>
 */
class AuthorizationCodeGrantTypeTest extends OAuth2GrantTypeTestCase
{

    protected function setUp()
    {
        parent::setUp();

        $authorizationCodeGrantType = new AuthorizationCode(
            $this->getClientAuthenticator(),
            $this->getClientStorage(),
            $this->getAuthorizationCodeStorage(),
            $this->getAccessTokenStorage(),
            $this->getScopeResolver()
        );

        $this->getClientStorage()->add(
            new Client(
                'public',
                null,
                [$authorizationCodeGrantType],
                [],
                null,
                'http://google.com'
            )
        );
        $this->getClientStorage()->add(
            new Client(
                'confidential',
                'secret',
                [$authorizationCodeGrantType],
                [],
                null,
                'http://google.com'
            )
        );

        $this->getGrantTypeResolver()->accept($authorizationCodeGrantType);
    }


    public function test_issue_access_tokens()
    {
        $request = new Request('GET', [], [], [
                'response_type' => 'code',
                'client_id' => 'public',
                'redirect_uri' => 'http://google.com',
                'state' => 'pom'
            ]
        );

        // request authorization from user
        $session = $this->getAuthorizator()->authorize($request, $user = new User('', '', [new Scope('edit')]));

        $this->assertInstanceOf(
            'OAuth2\Security\AuthorizationCodeSession',
            $session
        );
        $this->assertInstanceOf('OAuth2\Security\IAuthorizationSession', $session);
        $this->assertSame($user, $session->getUser());
        $this->assertInstanceOf('OAuth2\Storage\IClient', $session->getClient());
        $this->assertNotEmpty($session->getScopes());
        $this->assertEquals('pom', $session->getState());
        $this->assertEquals('http://google.com', $session->getAuthorizationCode()->getRedirectUri());
        $this->assertRegExp('~^http://google.com\?code=(\w+)&state=pom$~', $session->getRedirectUri());
    }


}
 