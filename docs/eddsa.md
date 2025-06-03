# EdDSA

One of the latest digital signature scheme that is deemed faster, more secure and simpler to implement compare with its counterpart e.g. RSA.

## Ed25519

Specific implemenation of EdDSA. You may need to use 

## Steps

### Generate a private/public key pair using Ed25519 algorithm 

```shell
openssl genpkey -algorithm Ed25519 -out private.key
openssl pkey -in private.key -pubout -out public.key
```

### Add authorization validator

You may extend the [Bearer token validator](https://github.com/thephpleague/oauth2-server/blob/master/src/AuthorizationValidators/BearerTokenValidator.php) if majority of the logic is almost identical or a totally different implementation as long as it implements `AuthorizationValidatorInterface`.

### Add yaml config

Add a custom yaml config on your project to set the custom authorization validator as `OauthServerController` dependency. You may need to pass other constructor parameters if needed.

```yaml
---
Name: oauth_server_controller_dependencies
---
IanSimpson\OAuth2\Entities\AccessTokenEntity:
  extensions:
    - App\DAM\OauthServer\AccessTokenEntityExtension

SilverStripe\Core\Injector\Injector:
  App\DAM\OauthServer\BearerTokenValidatorEddsa:
    constructor:
      - '%$IanSimpson\OAuth2\Repositories\AccessTokenRepository'
  IanSimpson\OAuth2\OauthServerController:
    properties:
      AuthorizationValidator: '%$App\DAM\OauthServer\BearerTokenValidatorEddsa'
```

### Update JWT Token

A public method is added to allow updating the generated access token in case the chosen algorithm does not match the token generator. To do so, add an extension to the `AccessTokenEntity` in your project and use the `updateJWT` hook. You may also refer to the [default token generator](https://github.com/thephpleague/oauth2-server/blob/master/src/Entities/Traits/AccessTokenTrait.php#L60), on the token format.
