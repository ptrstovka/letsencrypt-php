<?php

namespace Elphin\LEClient;

use Elphin\LEClient\Exception\LogicException;
use GuzzleHttp\Client;
use GuzzleHttp\ClientInterface;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;

/**
 * Main LetsEncrypt Client class, works as a framework for the LEConnector, LEAccount, LEOrder and
 * LEAuthorization classes.
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
class LEClient
{
    const LE_PRODUCTION = 'https://acme-v02.api.letsencrypt.org';
    const LE_STAGING = 'https://acme-staging-v02.api.letsencrypt.org';

    private $certificateKeys;
    private $accountKeys;

    private $connector;
    private $account;

    private $baseURL;

    /** @var LoggerInterface */
    private $log;

    /** @var ClientInterface */
    private $httpClient;

    /** @var DNS */
    private $dns;

    /** @var Sleep */
    private $sleep;

    private $email;

    /**
     * Initiates the LetsEncrypt main client.
     *
     * @param array $email The array of strings containing e-mail addresses. Only used in this function when
     *                                creating a new account.
     * @param string|bool $acmeURL ACME URL, can be string or one of predefined values: LE_STAGING or LE_PRODUCTION.
     *                                Defaults to LE_STAGING. Can also pass true/false for staging/production
     * @param LoggerInterface $logger PSR-3 compatible logger
     * @param ClientInterface|null $httpClient you can pass a custom client used for HTTP requests, if null is passed
     *                                one will be created
     * @param string|array $certificateKeys The main directory in which all keys (and certificates), including account
     *                                keys are stored. Defaults to 'keys/'. (optional)
     *                                Alternatively, can pass array containing location of all certificate files.
     *                                Required paths are public_key, private_key, order and
     *                                certificate/fullchain_certificate (you can use both or only one of them)
     * @param string|array $accountKeys The directory in which the account keys are stored. Is a subdir inside
     *                                $certificateKeys. Defaults to '__account/'.(optional)
     *                                Optional array containing location of account private and public keys.
     *                                Required paths are private_key, public_key.
     */
    public function __construct(
        $email,
        $acmeURL = LEClient::LE_STAGING,
        LoggerInterface $logger = null,
        ClientInterface $httpClient = null,
        $certificateKeys = 'keys/',
        $accountKeys = '__account/'
    ) {
        $this->log = $logger ?? new NullLogger();

        $this->initBaseUrl($acmeURL);
        $this->validateKeyConfig($certificateKeys, $accountKeys);

        $this->initCertificateKeys($certificateKeys);
        $this->initAccountKeys($certificateKeys, $accountKeys);

        $this->httpClient = $httpClient ?? new Client();
        $this->dns = new DNS;
        $this->sleep = new Sleep;
        $this->email = $email;
    }

    private function initBaseUrl($acmeURL)
    {
        if (is_bool($acmeURL)) {
            $this->baseURL = $acmeURL ? LEClient::LE_STAGING : LEClient::LE_PRODUCTION;
        } elseif (is_string($acmeURL)) {
            $this->baseURL = $acmeURL;
        } else {
            throw new LogicException('acmeURL must be set to string or bool (legacy)');
        }
    }

    public function getBaseUrl()
    {
        return $this->baseURL;
    }

    private function validateKeyConfig($certificateKeys, $accountKeys)
    {
        $ok = (is_array($certificateKeys) && is_array($accountKeys)) ||
            (is_string($certificateKeys) && is_string($accountKeys));
        if (!$ok) {
            throw new LogicException('certificateKeys and accountKeys must be both arrays, or both strings');
        }
    }

    private function initCertificateKeys($certificateKeys)
    {
        if (is_string($certificateKeys)) {
            if (!file_exists($certificateKeys)) {
                mkdir($certificateKeys, 0777, true);
                LEFunctions::createhtaccess($certificateKeys);
            }

            $this->certificateKeys = [
                "public_key" => $certificateKeys . '/public.pem',
                "private_key" => $certificateKeys . '/private.pem',
                "certificate" => $certificateKeys . '/certificate.crt',
                "fullchain_certificate" => $certificateKeys . '/fullchain.crt',
                "order" => $certificateKeys . '/order'
            ];
        } else {
            //it's an array
            if (!isset($certificateKeys['certificate']) || !isset($certificateKeys['fullchain_certificate'])) {
                throw new LogicException(
                    'certificateKeys[certificate] or certificateKeys[fullchain_certificate] file path must be set'
                );
            }
            if (!isset($certificateKeys['private_key'])) {
                throw new LogicException('certificateKeys[private_key] file path must be set');
            }
            if (!isset($certificateKeys['order'])) {
                $certificateKeys['order'] = dirname($certificateKeys['private_key']) . '/order';
            }
            if (!isset($certificateKeys['public_key'])) {
                $certificateKeys['public_key'] = dirname($certificateKeys['private_key']) . '/public.pem';
            }

            foreach ($certificateKeys as $param => $file) {
                $parentDir = dirname($file);
                if (!is_dir($parentDir)) {
                    throw new LogicException($parentDir . ' directory not found');
                }
            }

            $this->certificateKeys = $certificateKeys;
        }
    }

    private function initAccountKeys($certificateKeys, $accountKeys)
    {
        if (is_string($accountKeys)) {
            $accountKeys = $certificateKeys . '/' . $accountKeys;

            if (!file_exists($accountKeys)) {
                mkdir($accountKeys, 0777, true);
                LEFunctions::createhtaccess($accountKeys);
            }

            $this->accountKeys = [
                "private_key" => $accountKeys . '/private.pem',
                "public_key" => $accountKeys . '/public.pem'
            ];
        } else {
            //it's an array
            if (!isset($accountKeys['private_key'])) {
                throw new LogicException('accountKeys[private_key] file path must be set');
            }
            if (!isset($accountKeys['public_key'])) {
                throw new LogicException('accountKeys[public_key] file path must be set');
            }

            foreach ($accountKeys as $param => $file) {
                $parentDir = dirname($file);
                if (!is_dir($parentDir)) {
                    throw new LogicException($parentDir . ' directory not found');
                }
            }

            $this->accountKeys = $accountKeys;
        }
    }

    /**
     * Inject alternative DNS resolver for testing
     */
    public function setDNS(DNS $dns)
    {
        $this->dns = $dns;
    }

    /**
     * Inject alternative sleep service for testing
     */
    public function setSleep(Sleep $sleep)
    {
        $this->sleep = $sleep;
    }

    private function getConnector()
    {
        if (!isset($this->connector)) {
            $this->connector = new LEConnector($this->log, $this->httpClient, $this->baseURL, $this->accountKeys);

            //we need to initialize an account before using the connector
            $this->getAccount();
        }

        return $this->connector;
    }

    /**
     * Returns the LetsEncrypt account used in the current client.
     *
     * @return LEAccount    The LetsEncrypt Account instance used by the client.
     */
    public function getAccount()
    {
        if (!isset($this->account)) {
            $this->account = new LEAccount($this->getConnector(), $this->log, $this->email, $this->accountKeys);
        }
        return $this->account;
    }

    /**
     * Returns a LetsEncrypt order. If an order exists, this one is returned. If not, a new order is created and
     * returned.
     *
     * @param string $basename The base name for the order. Preferable the top domain (example.org). Will be the
     *                          directory in which the keys are stored. Used for the CommonName in the certificate as
     *                          well.
     * @param array $domains The array of strings containing the domain names on the certificate.
     * @param string $keyType Type of the key we want to use for certificate. Can be provided in ALGO-SIZE format
     *                          (ex. rsa-4096 or ec-256) or simple "rsa" and "ec" (using default sizes)
     * @param string $notBefore A date string formatted like 0000-00-00T00:00:00Z (yyyy-mm-dd hh:mm:ss) at which the
     *                          certificate becomes valid. Defaults to the moment the order is finalized. (optional)
     * @param string $notAfter A date string formatted like 0000-00-00T00:00:00Z (yyyy-mm-dd hh:mm:ss) until which the
     *                          certificate is valid. Defaults to 90 days past the moment the order is finalized.
     *                          (optional)
     *
     * @return LEOrder  The LetsEncrypt Order instance which is either retrieved or created.
     */
    public function getOrCreateOrder($basename, $domains, $keyType = 'rsa-4096', $notBefore = '', $notAfter = '')
    {
        $this->log->info("LEClient::getOrCreateOrder($basename,...)");

        return new LEOrder(
            $this->getConnector(),
            $this->log,
            $this->dns,
            $this->sleep,
            $this->certificateKeys,
            $basename,
            $domains,
            $keyType,
            $notBefore,
            $notAfter
        );
    }
}
