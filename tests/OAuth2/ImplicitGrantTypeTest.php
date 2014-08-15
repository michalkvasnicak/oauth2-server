<?php

namespace tests\OAuth2;

use OAuth2\GrantType\Implicit;
use OAuth2\TokenType\Bearer;
use tests\OAuth2\Fixtures\Client;
use tests\OAuth2\Fixtures\Request;
use tests\OAuth2\Fixtures\Scope;
use tests\OAuth2\Fixtures\User;
use tests\OAuth2GrantTypeTestCase;

/**
 * @author Michal Kvasničák <michal.kvasnicak@mink.sk>
 */
class ImplicitGrantTypeTest extends OAuth2GrantTypeTestCase
{


    protected function setUp()
    {
        parent::setUp();

        $implicitGrantType = new Implicit(
            $this->getClientStorage(),
            $this->getAccessTokenStorage(),
            $this->getScopeResolver(),
            new Bearer()
        );

        $this->getClientStorage()->add(
            new Client(
                'public',
                null,
                [$implicitGrantType],
                [new Scope('public'), new Scope('confidential')],
                null,
                'http://google.com'
            )
        );

        $this->getGrantTypeResolver()->accept($implicitGrantType);
    }


    public function test_issue_access_tokens()
    {
        $request = new Request('GET', [], [], [
                'response_type' => 'token',
                'client_id' => 'public',
                'redirect_uri' => 'http://google.com',
                'state' => 'pom'
            ]
        );

        // request authorization from user
        $session = $this->getAuthorizator()->authorize($request, $user = new User());

        $this->assertInstanceOf('OAuth2\Security\ImplicitSession', $session);
        $this->assertInstanceOf('OAuth2\Security\IAuthorizationSession', $session);

        $this->assertSame($user, $session->getUser());
        $this->assertInstanceOf('OAuth2\Storage\IClient', $session->getClient());
        $this->assertEquals('pom', $session->getState());
        $this->assertNotEmpty($session->getScopes());
        $this->assertRegExp('~^http://google.com#access_token=(\w+)&expires_in=\d+&scope=public\+confidential&state=pom&token_type=Bearer$~', $session->getRedirectUri());
    }

}
 