<?php
namespace Elphin\LEClient;

use Psr\Log\LoggerInterface;

/**
 * LetsEncrypt Account class, containing the functions and data associated with a LetsEncrypt account.
 *
 * PHP version 7.1.0
 *
 * MIT License
 *
 * Copyright (c) 2018 Youri van Weegberg
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * @author     Youri van Weegberg <youri@yourivw.nl>
 * @copyright  2018 Youri van Weegberg
 * @license    https://opensource.org/licenses/mit-license.php  MIT License
 * @version    1.1.0
 * @link       https://github.com/yourivw/LEClient
 * @since      Class available since Release 1.0.0
 */
class LEAccount
{
    private $connector;
    private $accountKeys;

    public $id;
    public $key;
    public $contact;
    public $agreement;
    public $initialIp;
    public $createdAt;
    public $status;

    /** @var LoggerInterface  */
    private $log;

    /**
     * Initiates the LetsEncrypt Account class.
     *
     * @param LEConnector $connector The LetsEncrypt Connector instance to use for HTTP requests.
     * @param LoggerInterface $log   PSR-3 compatible logger
     * @param array $email           The array of strings containing e-mail addresses. Only used when creating a
     *                               new account.
     * @param array $accountKeys     Array containing location of account keys files.
     */
    public function __construct($connector, LoggerInterface $log, $email, $accountKeys)
    {
        $this->connector = $connector;
        $this->accountKeys = $accountKeys;
        $this->log = $log;

        if (!file_exists($this->accountKeys['private_key']) or !file_exists($this->accountKeys['public_key'])) {
            $this->log->notice("No account found for ".implode(',', $email).", attempting to create account");

            LEFunctions::RSAgenerateKeys(null, $this->accountKeys['private_key'], $this->accountKeys['public_key']);
            $this->connector->accountURL = $this->createLEAccount($email);
        } else {
            $this->connector->accountURL = $this->getLEAccount();
        }
        if ($this->connector->accountURL === false) {
            throw new \RuntimeException('Account not found or deactivated.');
        }
        $this->getLEAccountData();
    }

    /**
     * Creates a new LetsEncrypt account.
     *
     * @param array     $email  The array of strings containing e-mail addresses.
     *
     * @return string|bool   Returns the new account URL when the account was successfully created, false if not.
     */
    private function createLEAccount($email)
    {
        $contact = array_map(function ($addr) {
            return empty($addr) ? '' : (strpos($addr, 'mailto') === false ? 'mailto:' . $addr : $addr);
        }, $email);

        $sign = $this->connector->signRequestJWK(
            ['contact' => $contact, 'termsOfServiceAgreed' => true],
            $this->connector->newAccount
        );
        $post = $this->connector->post($this->connector->newAccount, $sign);
        if (strpos($post['header'], "201 Created") !== false) {
            if (preg_match('~Location: (\S+)~i', $post['header'], $matches)) {
                return trim($matches[1]);
            }
        }
        return false;
    }

    /**
     * Gets the LetsEncrypt account URL associated with the stored account keys.
     *
     * @return string|bool   Returns the account URL if it is found, or false when none is found.
     */
    private function getLEAccount()
    {
        $sign = $this->connector->signRequestJWK(['onlyReturnExisting' => true], $this->connector->newAccount);
        $post = $this->connector->post($this->connector->newAccount, $sign);

        if (strpos($post['header'], "200 OK") !== false) {
            if (preg_match('~Location: (\S+)~i', $post['header'], $matches)) {
                return trim($matches[1]);
            }
        }
        return false;
    }

    /**
     * Gets the LetsEncrypt account data from the account URL.
     */
    private function getLEAccountData()
    {
        $sign = $this->connector->signRequestKid(
            ['' => ''],
            $this->connector->accountURL,
            $this->connector->accountURL
        );
        $post = $this->connector->post($this->connector->accountURL, $sign);
        if (strpos($post['header'], "200 OK") !== false) {
            $this->id = $post['body']['id'];
            $this->key = $post['body']['key'];
            $this->contact = $post['body']['contact'];
            $this->agreement = $post['body']['agreement'];
            $this->initialIp = $post['body']['initialIp'];
            $this->createdAt = $post['body']['createdAt'];
            $this->status = $post['body']['status'];
        } else {
            throw new \RuntimeException('Account data cannot be found.');
        }
    }

    /**
     * Updates account data. Now just supporting new contact information.
     *
     * @param array     $email  The array of strings containing e-mail adresses.
     *
     * @return boolean  Returns true if the update is successful, false if not.
     */
    public function updateAccount($email)
    {
        $contact = array_map(function ($addr) {
            return empty($addr) ? '' : (strpos($addr, 'mailto') === false ? 'mailto:' . $addr : $addr);
        }, $email);

        $sign = $this->connector->signRequestKid(
            ['contact' => $contact],
            $this->connector->accountURL,
            $this->connector->accountURL
        );
        $post = $this->connector->post($this->connector->accountURL, $sign);
        if (strpos($post['header'], "200 OK") !== false) {
            $this->id = $post['body']['id'];
            $this->key = $post['body']['key'];
            $this->contact = $post['body']['contact'];
            $this->agreement = $post['body']['agreement'];
            $this->initialIp = $post['body']['initialIp'];
            $this->createdAt = $post['body']['createdAt'];
            $this->status = $post['body']['status'];

            $this->log->notice('Account data updated');
            return true;
        } else {
            return false;
        }
    }

    /**
     * Creates new RSA account keys and updates the keys with LetsEncrypt.
     *
     * @return boolean  Returns true if the update is successful, false if not.
     */
    public function changeAccountKeys()
    {
        LEFunctions::RSAgenerateKeys(
            null,
            $this->accountKeys['private_key'].'.new',
            $this->accountKeys['public_key'].'.new'
        );
        $privateKey = openssl_pkey_get_private(file_get_contents($this->accountKeys['private_key'].'.new'));
        if ($privateKey === false) {
            $this->log->error('LEAccount::changeAccountKeys failed to open private key');
            return false;
        }

        $details = openssl_pkey_get_details($privateKey);
        $innerPayload = ['account' => $this->connector->accountURL, 'newKey' => [
            "kty" => "RSA",
            "n" => LEFunctions::base64UrlSafeEncode($details["rsa"]["n"]),
            "e" => LEFunctions::base64UrlSafeEncode($details["rsa"]["e"])
        ]];
        $outerPayload = $this->connector->signRequestJWK(
            $innerPayload,
            $this->connector->keyChange,
            $this->accountKeys['private_key'].'.new'
        );
        $sign = $this->connector->signRequestKid(
            $outerPayload,
            $this->connector->accountURL,
            $this->connector->keyChange
        );
        $post = $this->connector->post($this->connector->keyChange, $sign);
        if (strpos($post['header'], "200 OK") !== false) {
            $this->getLEAccountData();

            unlink($this->accountKeys['private_key']);
            unlink($this->accountKeys['public_key']);
            rename($this->accountKeys['private_key'].'.new', $this->accountKeys['private_key']);
            rename($this->accountKeys['public_key'].'.new', $this->accountKeys['public_key']);

            $this->log->notice('Account keys changed');
            return true;
        } else {
            return false;
        }
    }

    /**
     * Deactivates the LetsEncrypt account.
     *
     * @return boolean  Returns true if the deactivation is successful, false if not.
     */
    public function deactivateAccount()
    {
        $sign = $this->connector->signRequestKid(
            ['status' => 'deactivated'],
            $this->connector->accountURL,
            $this->connector->accountURL
        );
        $post = $this->connector->post($this->connector->accountURL, $sign);
        if (strpos($post['header'], "200 OK") !== false) {
            $this->connector->accountDeactivated = true;
            $this->log->info('Account deactivated');
            return true;
        }

        return false;
    }
}
