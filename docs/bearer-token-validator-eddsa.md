There is no available validator for EdDSA tokens, as the `league/oauth2-server` package does not currently support this algorithm. If you need to use EdDSA tokens, you will need to implement your own custom validator that extends the `BearerTokenValidator` class or implement the `AuthorizationValidatorInterface` and add the necessary logic to validate EdDSA token.

One key difference between EdDSA validator is the signer used on the JWT Configuration class. The default uses `Sha256` as the signer, while the EdDSA validator uses `Eddsa` as the signer. Both are found in the `lcobucci/jwt` package.

BearerTokenValidator:
```php
$this->jwtConfiguration = Configuration::forSymmetricSigner(
    new Sha256(),
    InMemory::plainText('empty', 'empty')
);
```

EdDSA Validator:
```php
$this->jwtConfiguration = Configuration::forSymmetricSigner(
    new Eddsa(),
    InMemory::plainText('empty', 'empty')
);
```
