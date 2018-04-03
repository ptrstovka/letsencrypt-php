<?php
namespace Elphin\LEClient;

use Elphin\LEClient\Exception\LogicException;
use Elphin\LEClient\Exception\RuntimeException;

/**
 * LetsEncrypt Functions class, supplying the LetsEncrypt Client with supportive functions.
 *
 * @author     Youri van Weegberg <youri@yourivw.nl>
 * @copyright  2018 Youri van Weegberg
 * @license    https://opensource.org/licenses/mit-license.php  MIT License
 */
class LEFunctions
{
    /**
     * Generates a new RSA keypair and saves both keys to a new file.
     *
     * @param string $directory      The directory in which to store the new keys. If set to null or empty string -
     *                               privateKeyFile and publicKeyFile will be treated as absolute paths.
     * @param string $privateKeyFile The filename for the private key file.
     * @param string $publicKeyFile  The filename for the public key file.
     * @param integer $keySize       RSA key size, must be between 2048 and 4096 (default is 4096)
     */
    public static function RSAGenerateKeys(
        $directory,
        $privateKeyFile = 'private.pem',
        $publicKeyFile = 'public.pem',
        $keySize = 4096
    ) {

        if ($keySize < 2048 || $keySize > 4096) {
            throw new LogicException("RSA key size must be between 2048 and 4096");
        }

        $res = openssl_pkey_new([
            "private_key_type" => OPENSSL_KEYTYPE_RSA,
            "private_key_bits" => intval($keySize),
        ]);

        if (!openssl_pkey_export($res, $privateKey)) {
            throw new RuntimeException("RSA keypair export failed!"); //@codeCoverageIgnore
        }

        $details = openssl_pkey_get_details($res);

        if ($directory !== null && $directory !== '') {
            $privateKeyFile = $directory.$privateKeyFile;
            $publicKeyFile = $directory.$publicKeyFile;
        }

        file_put_contents($privateKeyFile, $privateKey);
        file_put_contents($publicKeyFile, $details['key']);

        openssl_pkey_free($res);
    }



    /**
     * Generates a new EC prime256v1 keypair and saves both keys to a new file.
     *
     * @param string $directory      The directory in which to store the new keys. If set to null or empty string -
     *                               privateKeyFile and publicKeyFile will be treated as absolute paths.
     * @param string $privateKeyFile The filename for the private key file.
     * @param string $publicKeyFile  The filename for the public key file.
     * @param integer $keySize       EC key size, possible values are 256 (prime256v1) or 384 (secp384r1),
     *                               default is 256
     */
    public static function ECGenerateKeys(
        $directory,
        $privateKeyFile = 'private.pem',
        $publicKeyFile = 'public.pem',
        $keySize = 256
    ) {
        if (version_compare(PHP_VERSION, '7.1.0') == -1) {
            throw new RuntimeException("PHP 7.1+ required for EC keys"); //@codeCoverageIgnore
        }

        if ($keySize == 256) {
                $res = openssl_pkey_new([
                        "private_key_type" => OPENSSL_KEYTYPE_EC,
                        "curve_name" => "prime256v1",
                ]);
        } elseif ($keySize == 384) {
                $res = openssl_pkey_new([
                        "private_key_type" => OPENSSL_KEYTYPE_EC,
                        "curve_name" => "secp384r1",
                ]);
        } else {
            throw new LogicException("EC key size must be 256 or 384");
        }


        if (!openssl_pkey_export($res, $privateKey)) {
            throw new RuntimeException("EC keypair export failed!"); //@codeCoverageIgnore
        }

        $details = openssl_pkey_get_details($res);

        if ($directory !== null && $directory !== '') {
            $privateKeyFile = $directory.$privateKeyFile;
            $publicKeyFile = $directory.$publicKeyFile;
        }

        file_put_contents($privateKeyFile, $privateKey);
        file_put_contents($publicKeyFile, $details['key']);

        openssl_pkey_free($res);
    }



    /**
     * Encodes a string input to a base64 encoded string which is URL safe.
     *
     * @param string    $input  The input string to encode.
     *
     * @return string   Returns a URL safe base64 encoded string.
     */
    public static function base64UrlSafeEncode($input)
    {
        return str_replace('=', '', strtr(base64_encode($input), '+/', '-_'));
    }

    /**
     * Decodes a string that is URL safe base64 encoded.
     *
     * @param string    $input  The encoded input string to decode.
     *
     * @return string   Returns the decoded input string.
     */
    public static function base64UrlSafeDecode($input)
    {
        $remainder = strlen($input) % 4;
        if ($remainder) {
            $padlen = 4 - $remainder;
            $input .= str_repeat('=', $padlen);
        }
        return base64_decode(strtr($input, '-_', '+/'));
    }

    /**
     * Makes a request to the HTTP challenge URL and checks whether the authorization is valid for the given $domain.
     *
     * @param string    $domain             The domain to check the authorization for.
     * @param string    $token              The token (filename) to request.
     * @param string    $keyAuthorization   the keyAuthorization (file content) to compare.
     *
     * @return boolean  Returns true if the challenge is valid, false if not.
     * @codeCoverageIgnore
     */
    public static function checkHTTPChallenge($domain, $token, $keyAuthorization)
    {
        $requestURL = $domain . '/.well-known/acme-challenge/' . $token;
        $handle = curl_init();
        curl_setopt($handle, CURLOPT_URL, $requestURL);
        curl_setopt($handle, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($handle, CURLOPT_FOLLOWLOCATION, true);
        $response = curl_exec($handle);
        return (!empty($response) && $response == $keyAuthorization);
    }




    /**
     * Creates a simple .htaccess file in $directory which denies from all.
     *
     * @param string    $directory  The directory in which to put the .htaccess file.
     */
    public static function createhtaccess($directory)
    {
        file_put_contents($directory . '.htaccess', "order deny,allow\ndeny from all");
    }
}
