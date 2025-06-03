# OAuth2 Server

## Introduction 👋

This allows your Silverstripe site to be in OAuth 2.0 provider.

Please note that this is under development. It should work just fine, but has not been extensively tested, and is poorly documented.

It supports the following grants:

 * Authorization code grant
 * Refresh grant

## Requirements 🦺

 * PHP ^8.1
 * Silverstripe ^4.13

## Installation 👷‍♀️

Install the add-on with Composer:

```sh
composer require iansimpson/ss-oauth2-server
```

Next, generate a private/public key pair:

```sh
openssl genrsa -out private.key 2048
openssl rsa -in private.key -pubout -out public.key
chmod 600 private.key
chmod 600 public.key
```

Put these on your web server, somewhere outside the web root

Generate encryption key:

```sh
php -r 'echo base64_encode(random_bytes(36)), PHP_EOL;'
```

Add the following lines in your `.env`, updating the `OAUTH_PRIVATE_KEY_PATH` and `OAUTH_PUBLIC_KEY_PATH` to point to the key files, and adding the encryption key you have just generated:

```env
OAUTH_PRIVATE_KEY_PATH="/path/to/my/private.key"
OAUTH_PUBLIC_KEY_PATH="/path/to/my/public.key"
OAUTH_ENCRYPTION_KEY="my-encryption-key"
```

Finally, after doing a `/dev/build/` go into your site settings and on the OAuth Configuration and add a new Client. Using this you should now be able to generate a key at `/oauth/authorize`, per the OAuth 2.0 spec (https://tools.ietf.org/html/rfc6749).

## Usage 🏃🏃🏃

To verify the Authorization header being submitted is correct, add this to your Controller:

```php
$member = IanSimpson\OAuth2\OauthServerController::getMember($this);
```

it will return a Member object if the Authorization header is correct, or null if there's an error. Simple!
