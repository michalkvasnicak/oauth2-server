# OAuth 2.0 server for PHP and HHVM
---

* Develop: [![Build Status](https://travis-ci.org/michalkvasnicak/oauth2-server.svg?branch=develop)](https://travis-ci.org/michalkvasnicak/oauth2-server)
* Master: [![Build Status](https://travis-ci.org/michalkvasnicak/oauth2-server.svg?branch=master)](https://travis-ci.org/michalkvasnicak/oauth2-server)

OAuth 2.0 server implementation of final draft [http://tools.ietf.org/html/rfc6749](http://tools.ietf.org/html/rfc6749)

Examples of using different grant types are in tests directory.

This library is not tested in production.


## Requirements
---

* PHP >= 5.4.0
* HHVM

## Installation

Using composer:

```json
{
    "require": {
        "michalkvasnicak/oauth2-server": "dev-develop"
    }
}
```
## Example

### Grant access to application (client)

Used by authorization code and implicit grant types

```php
<?php

use OAuth2\Security\Authorizator;
use OAuth2\Resolver\GrantTypeResolver;

$request = new Request; // here create request from globals or whatever

$grantTypeResolver = new GrantTypeResolver;
$grantTypeResolver->accept($grantType); // register OAuth2\GrantType\IGrantType or OAuth2\GrantType\IAuthorizationType

$authorizator = new Authorizator($grantTypeResolver);

// for authorizing you have to provide current request and logged user
$session = $authorizator->authorize($request, $user); 
// returns OAuth2\Security\AuthorizationCodeSession

// there you show form with requested scopes and asks user to accept / deny this request
// you can redirect user if you allow user to access resource to redirect uri from auth session

$session->getRedirectUri(); // returns redirect uri with code and state (if state was provided)
```


### Issue access token to current request (using one of registered grant types)

```php
<?php

use OAuth2\TokenIssuer\AccessTokenIssuer;
use OAuth2\Resolver\GrantTypeResolver;

$request = new Request; // here create request from globals or whatever, implement OAuth2\Http\IRequest

$grantTypeResolver = new GrantTypeResolver;

$grantTypeResolver->accept($grantType); // register OAuth2\GrantType\IGrantType 

$accessTokenIssuer = new AccessTokenIssuer($grantTypeResolver);

// access token lifetime is handled by access token storage
$accessToken = $accessTokenIssuer->issueToken($request); // returns OAuth2\Storage\IAccessToken

// refresh token has to be issued manually
$refreshTokenIssuer = new RefreshTokenIssuer($refreshTokenStorage);

// refresh token lifetime is handled by refresh token storage

$refreshTokenIssuer->issueToken($accessToken); // returns OAuth2\Storage\IRefreshToken
```

### Authenticate user for current request and authorize access to resource

```php
<?php

use OAuth2\Security\Authenticator;
use OAuth2\Resolver\TokenTypeResolver;
use OAuth2\TokenType\Bearer;


$accessTokenStorage = ...; // implementation of OAuth2\Storage\IAccessTokenStorage

// register accepted token types
$tokenTypeResolver = new TokenTypeResolver;
$tokenTypeResolver->accept($tokenType); // accepted token type OAuth2\TokenType\ITokenType

$authenticator = new Authenticator(
    $tokenTypeResolver,
    $accessTokenStorage
);

$currentSession = $authenticator->authenticate($request); // returns OAuth2\Security\Session

$currentSession->isAllowed('edit'); // checks if current access token has given scope, returns boolean

// get logged user
$currentSession->getUser(); // OAuth2\Storage\IUser

// get access token
$currentSession->getAccessToken(); // OAuth2\Storage\IAccessToken

// get client used to connect
$currentSession->getClient(); //OAuth2\Storage\IClient
```
