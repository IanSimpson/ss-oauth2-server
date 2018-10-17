# OAuth2 Server

## Introduction

This allows your Silverstripe site to be in OAuth 2.0 provider.

Please note that this is under development. It should work just fine, but has not been extensively tested, and is poorly documented.

It supports the following grants:

 * Authorization code grant
 * Refresh grant

## Requirements

 * SilverStripe 3.x

## Installation

Install the add-on with Composer:

```
composer require iansimpson/ss-oauth2-server
```

Next, generate a private/public key pair:

```
openssl genrsa -out private.key 2048
openssl rsa -in private.key -pubout -out public.key
chmod 600 private.key
chmod 600 public.key
```

Put these on your web server, somewhere outside the web root

Generate encryption key:

```
php -r 'echo base64_encode(random_bytes(32)), PHP_EOL;'
```

Add the following lines in your `mysite/_config/config.yml`, updating the privateKey and publicKey to point to the key files (relative to the SilverStripe root), and adding the encryption key you have just generated:

```
IanSimpson\OAuth2\OauthServerController:
  privateKey: '../private.key'
  publicKey: '../public.key'
  encryptionKey: 'l4kZ/YXA1HJp7vLjB7IeDsIR3GEy6Kojfr+N+UalwkU= # example only, generate your own.'
```

Finally, after doing a `/dev/build/` go into your site settings and on the OAuth Configuration and add a new Client. Using this you should now be able to generate a key at `/oauth/authorize`, per the OAuth 2.0 spec (https://tools.ietf.org/html/rfc6749).

## Usage

To verify the Authorization header being submitted is correct, add this to your Controller:

```
$member = IanSimpson\OAuth2\OauthServerController::getMember($this);
```

it will return a Member object if the Authorization header is correct, or false if there's an error. Simple!
