<?php

namespace IanSimpson\OAuth2\Utility;

/**
 * Contains helper functions that can be used across
 */
class Utility
{

    /**
     * Converts the given PEM key generated from `openssl` to DER format and extracts the last 32 bytes.
     * If a private key (private.key) is provided, the last 32 bytes represent the private key which can be used
     * for generating Sodium-compatible key format.
     *
     * If a public key (public.key) is provided, the last 32 bytes represent the Sodium-compatible public key that can
     * be used for validation.
     *
     * @param string $pemKey
     * @return string
     */
    public static function extractDERKeyValue(string $pemKey)
    {
        $derKey = base64_decode(preg_replace('/-+.*?-+|\s/', '', $pemKey));

        return substr($derKey, -32);
    }
}
