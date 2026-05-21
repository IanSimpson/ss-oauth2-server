## Access Token Entity Extension

Add an extension to the `AccessTokenEntity` in your project and use the `updateJWT` hook.

Example
```php

use DateTimeImmutable;
use IanSimpson\OAuth2\Entities\AccessTokenEntity;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Eddsa;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Token;
use League\OAuth2\Server\CryptKeyInterface;
use SilverStripe\Core\Extension;
use Throwable;

public static function extractDERKeyValue(string $pemKey): string
{
    if (empty($pemKey)) {
        return '';
    }

    $derKey = base64_decode(preg_replace('/-+.*?-+|\s/', '', $pemKey));

    return substr($derKey, -32);
}

public function updateJWT(?Token &$token, ?CryptKeyInterface $privateKey): void
{
    /** @var AccessTokenEntity $owner */
    $owner = $this->getOwner();

    // Extract the PEM key generated
    $pemPrivateKey = $privateKey?->getKeyContents() ?? '';

    // Extract the DER formatted key to use as seed for generating the private/secret key
    $derKey = self::extractDERKeyValue($pemPrivateKey);

    // Generate the key pairs via Sodium library
    $keypair = sodium_crypto_sign_seed_keypair($derKey);
    $secretkey = sodium_crypto_sign_secretkey($keypair);
    $pubKey = sodium_crypto_sign_publickey($keypair);

    // Configure the JWT generation
    $config = Configuration::forAsymmetricSigner(
        new Eddsa(),
        InMemory::plainText($secretkey),
        InMemory::plainText($pubKey)
    );

    // return the token
    $token = $config->builder()
        ->permittedFor($owner->getClient()->getIdentifier())
        ->identifiedBy($owner->getIdentifier())
        ->issuedAt(new DateTimeImmutable())
        ->canOnlyBeUsedAfter(new DateTimeImmutable())
        ->expiresAt($owner->getExpiryDateTime())
        ->relatedTo($owner->getUserIdentifier())
        ->withClaim('scopes', $owner->getScopes())
        ->getToken($config->signer(), $config->signingKey());
}
```

### Notes
This extension demonstrates how to generate an EdDSA-signed JWT using a PEM-encoded private key and PHP's Sodium library, replacing the default JWT produced by the OAuth2 server.
- **PEM to DER conversion:** `Utility::extractDERKeyValue()` converts the PEM private key to its raw DER value. This is required because `sodium_crypto_sign_seed_keypair()` expects a raw 32-byte seed, not a PEM-encoded string.
- **EdDSA (Ed25519) signing:** This uses the EdDSA algorithm (`Ed25519`) via `lcobucci/jwt`. Unlike RSA (`RS256`) or HMAC (`HS256`), EdDSA is an asymmetric algorithm based on elliptic curves, offering strong security with smaller key sizes and fast signing/verification.
- **Verification key placeholder:** `InMemory::plainText('empty', 'empty')` is passed as the verification key in `Configuration::forAsymmetricSigner()`. This is only a placeholder for token generation. Any consumer validating the token must supply the corresponding Ed25519 **public key**.
- **Scopes serialised as array:** `withClaim('scopes', $owner->getScopes())` stores scopes as an array in the JWT payload. Downstream validators and token parsers must handle this as an array rather than a space-delimited string.

