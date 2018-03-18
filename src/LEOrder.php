<?php

namespace Elphin\LEClient;

use Elphin\LEClient\Exception\LogicException;
use Elphin\LEClient\Exception\RuntimeException;
use Psr\Log\LoggerInterface;

/**
 * LetsEncrypt Order class, containing the functions and data associated with a specific LetsEncrypt order.
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
 */
class LEOrder
{
    /** @var LEConnector */
    private $connector;

    private $basename;
    private $certificateKeys;
    private $orderURL;
    private $keyType;
    private $keySize;

    public $status;
    public $expires;
    public $identifiers;
    private $authorizationURLs;

    /** @var LEAuthorization[] */
    public $authorizations;
    public $finalizeURL;
    public $certificateURL;

    /** @var LoggerInterface */
    private $log;

    /** @var DNS */
    private $dns;

    /** @var Sleep */
    private $sleep;

    const CHALLENGE_TYPE_HTTP = 'http-01';
    const CHALLENGE_TYPE_DNS = 'dns-01';

    /**
     * Initiates the LetsEncrypt Order class. If the base name is found in the $keysDir directory, the order data is
     * requested. If no order was found locally, if the request is invalid or when there is a change in domain names, a
     * new order is created.
     *
     * @param LEConnector $connector The LetsEncrypt Connector instance to use for HTTP requests.
     * @param LoggerInterface $log PSR-3 compatible logger
     * @param DNS $dns DNS challenge checking service
     * @param Sleep $sleep Sleep service for polling
     */
    public function __construct(
        LEConnector $connector,
        LoggerInterface $log,
        DNS $dns,
        Sleep $sleep
    ) {
        $this->connector = $connector;
        $this->log = $log;
        $this->dns = $dns;
        $this->sleep = $sleep;
    }

    /**
     * Loads or updates an order. If the base name is found in the $keysDir directory, the order data is
     * requested. If no order was found locally, if the request is invalid or when there is a change in domain names, a
     * new order is created.
     *
     * @param array $certificateKeys Array containing location of certificate keys files.
     * @param string $basename The base name for the order. Preferable the top domain (example.org).
     *                                         Will be the directory in which the keys are stored. Used for the
     *                                         CommonName in the certificate as well.
     * @param array $domains The array of strings containing the domain names on the certificate.
     * @param string $keyType Type of the key we want to use for certificate. Can be provided in
     *                                         ALGO-SIZE format (ex. rsa-4096 or ec-256) or simply "rsa" and "ec"
     *                                         (using default sizes)
     * @param string $notBefore A date string formatted like 0000-00-00T00:00:00Z (yyyy-mm-dd hh:mm:ss)
     *                                         at which the certificate becomes valid.
     * @param string $notAfter A date string formatted like 0000-00-00T00:00:00Z (yyyy-mm-dd hh:mm:ss)
     *                                         until which the certificate is valid.
     */
    public function loadOrder(array $certificateKeys, $basename, array $domains, $keyType, $notBefore, $notAfter)
    {
        $this->basename = $basename;
        $this->certificateKeys = $certificateKeys;
        $this->initialiseKeyTypeAndSize($keyType ?? 'rsa-4096');

        if ($this->loadExistingOrder($domains)) {
            $this->updateAuthorizations();
        } else {
            $this->createOrder($domains, $notBefore, $notAfter);
        }
    }

    private function loadExistingOrder($domains)
    {
        //anything to load?
        if (!file_exists($this->certificateKeys['private_key']) ||
            !file_exists($this->certificateKeys['order']) ||
            !file_exists($this->certificateKeys['public_key'])
        ) {
            $this->log->info("No order found for {$this->basename}. Creating new order.");
            return false;
        }

        //valid URL?
        $this->orderURL = file_get_contents($this->certificateKeys['order']);
        if (!filter_var($this->orderURL, FILTER_VALIDATE_URL)) {
            //@codeCoverageIgnoreStart
            $this->log->warning("Order for {$this->basename} has invalid URL. Creating new order.");
            $this->deleteOrderFiles();
            return false;
            //@codeCoverageIgnoreEnd
        }

        //retrieve the order
        $get = $this->connector->get($this->orderURL);
        if (strpos($get['header'], "200 OK") === false) {
            //@codeCoverageIgnoreStart
            $this->log->warning("Order for {$this->basename} invalid. Creating new order.");
            $this->deleteOrderFiles();
            return false;
            //@codeCoverageIgnoreEnd
        }

        //ensure retrieved order matches our domains
        $orderdomains = array_map(function ($ident) {
            return $ident['value'];
        }, $get['body']['identifiers']);
        $diff = array_merge(array_diff($orderdomains, $domains), array_diff($domains, $orderdomains));
        if (!empty($diff)) {
            $this->log->warning('Domains do not match order data. Deleting and creating new order.');
            $this->deleteOrderFiles();
            return false;
        }

        //the order is good
        $this->status = $get['body']['status'];
        $this->expires = $get['body']['expires'];
        $this->identifiers = $get['body']['identifiers'];
        $this->authorizationURLs = $get['body']['authorizations'];
        $this->finalizeURL = $get['body']['finalize'];
        if (array_key_exists('certificate', $get['body'])) {
            $this->certificateURL = $get['body']['certificate'];
        }

        return true;
    }

    private function deleteOrderFiles()
    {
        foreach ($this->certificateKeys as $file) {
            if (is_file($file)) {
                unlink($file);
            }
        }
    }

    private function initialiseKeyTypeAndSize($keyType)
    {
        if ($keyType == 'rsa') {
            $this->keyType = 'rsa';
            $this->keySize = 4096;
        } elseif ($keyType == 'ec') {
            $this->keyType = 'ec';
            $this->keySize = 256;
        } else {
            preg_match_all('/^(rsa|ec)\-([0-9]{3,4})$/', $keyType, $keyTypeParts, PREG_SET_ORDER, 0);

            if (!empty($keyTypeParts)) {
                $this->keyType = $keyTypeParts[0][1];
                $this->keySize = intval($keyTypeParts[0][2]);
            } else {
                throw new LogicException('Key type \'' . $keyType . '\' not supported.');
            }
        }
    }

    /**
     * Creates a new LetsEncrypt order and fills this instance with its data. Subsequently creates a new RSA keypair
     * for the certificate.
     *
     * @param array $domains The array of strings containing the domain names on the certificate.
     * @param string $notBefore A date string formatted like 0000-00-00T00:00:00Z (yyyy-mm-dd hh:mm:ss)
     *                          at which the certificate becomes valid.
     * @param string $notAfter A date string formatted like 0000-00-00T00:00:00Z (yyyy-mm-dd hh:mm:ss)
     *                          until which the certificate is valid.
     */
    private function createOrder($domains, $notBefore, $notAfter)
    {
        if (preg_match('~(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z|^$)~', $notBefore) and
            preg_match('~(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z|^$)~', $notAfter)
        ) {
            $dns = [];
            foreach ($domains as $domain) {
                if (preg_match_all('~(\*\.)~', $domain) > 1) {
                    throw new LogicException('Cannot create orders with multiple wildcards in one domain.');
                }
                $dns[] = ['type' => 'dns', 'value' => $domain];
            }
            $payload = ["identifiers" => $dns, 'notBefore' => $notBefore, 'notAfter' => $notAfter];
            $sign = $this->connector->signRequestKid(
                $payload,
                $this->connector->accountURL,
                $this->connector->newOrder
            );
            $post = $this->connector->post($this->connector->newOrder, $sign);

            if (strpos($post['header'], "201 Created") !== false) {
                if (preg_match('~Location: (\S+)~i', $post['header'], $matches)) {
                    $this->orderURL = trim($matches[1]);
                    file_put_contents($this->certificateKeys['order'], $this->orderURL);
                    if ($this->keyType == "rsa") {
                        LEFunctions::RSAgenerateKeys(
                            null,
                            $this->certificateKeys['private_key'],
                            $this->certificateKeys['public_key'],
                            $this->keySize
                        );
                    } else {
                        LEFunctions::ECgenerateKeys(
                            null,
                            $this->certificateKeys['private_key'],
                            $this->certificateKeys['public_key'],
                            $this->keySize
                        );
                    }

                    $this->status = $post['body']['status'];
                    $this->expires = $post['body']['expires'];
                    $this->identifiers = $post['body']['identifiers'];
                    $this->authorizationURLs = $post['body']['authorizations'];
                    $this->finalizeURL = $post['body']['finalize'];
                    if (array_key_exists('certificate', $post['body'])) {
                        $this->certificateURL = $post['body']['certificate'];
                    }
                    $this->updateAuthorizations();

                    $this->log->info('Created order for ' . $this->basename);
                } else {
                    throw new RuntimeException('New-order returned invalid response.');
                }
            } else {
                throw new RuntimeException('Creating new order failed.');
            }
        } else {
            throw new LogicException(
                'notBefore and notAfter fields must be empty ' .
                'or be a string similar to 0000-00-00T00:00:00Z'
            );
        }
    }

    /**
     * Fetches the latest data concerning this LetsEncrypt Order instance and fills this instance with the new data.
     */
    private function updateOrderData()
    {
        $get = $this->connector->get($this->orderURL);
        if (strpos($get['header'], "200 OK") !== false) {
            $this->status = $get['body']['status'];
            $this->expires = $get['body']['expires'];
            $this->identifiers = $get['body']['identifiers'];
            $this->authorizationURLs = $get['body']['authorizations'];
            $this->finalizeURL = $get['body']['finalize'];
            if (array_key_exists('certificate', $get['body'])) {
                $this->certificateURL = $get['body']['certificate'];
            }
            $this->updateAuthorizations();
        } else {
            //@codeCoverageIgnoreStart
            $this->log->error("Failed to fetch order for {$this->basename}");
            //@codeCoverageIgnoreEnd
        }
    }

    /**
     * Fetches the latest data concerning all authorizations connected to this LetsEncrypt Order instance and
     * creates and stores a new LetsEncrypt Authorization instance for each one.
     */
    private function updateAuthorizations()
    {
        $this->authorizations = [];
        foreach ($this->authorizationURLs as $authURL) {
            if (filter_var($authURL, FILTER_VALIDATE_URL)) {
                $auth = new LEAuthorization($this->connector, $this->log, $authURL);
                if ($auth != false) {
                    $this->authorizations[] = $auth;
                }
            }
        }
    }

    /**
     * Walks all LetsEncrypt Authorization instances and returns whether they are all valid (verified).
     *
     * @return boolean  Returns true if all authorizations are valid (verified), returns false if not.
     */
    public function allAuthorizationsValid()
    {
        if (count($this->authorizations) > 0) {
            foreach ($this->authorizations as $auth) {
                if ($auth->status != 'valid') {
                    return false;
                }
            }
            return true;
        }
        return false;
    }

    private function loadAccountKey()
    {
        $privateKey = openssl_pkey_get_private(file_get_contents($this->connector->accountKeys['private_key']));
        if ($privateKey === false) {
            //@codeCoverageIgnoreStart
            throw new RuntimeException("Failed load account key from " . $this->connector->accountKeys['private_key']);
            //@codeCoverageIgnoreEnd
        }
        return $privateKey;
    }


    private function loadCertificateKey()
    {
        $privateKey = openssl_pkey_get_private(file_get_contents($this->certificateKeys['private_key']));
        if ($privateKey === false) {
            //@codeCoverageIgnoreStart
            throw new RuntimeException("Failed load certificate key from " . $this->certificateKeys['private_key']);
            //@codeCoverageIgnoreEnd
        }
        return $privateKey;
    }

    /**
     * Get all pending LetsEncrypt Authorization instances and return the necessary data for verification.
     * The data in the return object depends on the $type.
     *
     * @param string $type The type of verification to get. Supporting http-01 and dns-01.
     *                     Supporting LEOrder::CHALLENGE_TYPE_HTTP and LEOrder::CHALLENGE_TYPE_DNS. Throws a Runtime
     *                     Exception when requesting an unknown $type. Keep in mind a wildcard domain authorization only
     *                     accepts LEOrder::CHALLENGE_TYPE_DNS.
     *
     * @return array|bool Returns an array with verification data if successful, false if not pending LetsEncrypt
     *                  Authorization instances were found. The return array always
     *                  contains 'type' and 'identifier'. For LEOrder::CHALLENGE_TYPE_HTTP, the array contains
     *                  'filename' and 'content' for necessary the authorization file.
     *                  For LEOrder::CHALLENGE_TYPE_DNS, the array contains 'DNSDigest', which is the content for the
     *                  necessary DNS TXT entry.
     */

    public function getPendingAuthorizations($type)
    {
        $authorizations = [];

        $privateKey = $this->loadAccountKey();
        $details = openssl_pkey_get_details($privateKey);

        $header = [
            "e" => LEFunctions::base64UrlSafeEncode($details["rsa"]["e"]),
            "kty" => "RSA",
            "n" => LEFunctions::base64UrlSafeEncode($details["rsa"]["n"])

        ];
        $digest = LEFunctions::base64UrlSafeEncode(hash('sha256', json_encode($header), true));

        foreach ($this->authorizations as $auth) {
            if ($auth->status == 'pending') {
                $challenge = $auth->getChallenge($type);
                if ($challenge['status'] == 'pending') {
                    $keyAuthorization = $challenge['token'] . '.' . $digest;
                    switch (strtolower($type)) {
                        case LEOrder::CHALLENGE_TYPE_HTTP:
                            $authorizations[] = [
                                'type' => LEOrder::CHALLENGE_TYPE_HTTP,
                                'identifier' => $auth->identifier['value'],
                                'filename' => $challenge['token'],
                                'content' => $keyAuthorization
                            ];
                            break;
                        case LEOrder::CHALLENGE_TYPE_DNS:
                            $DNSDigest = LEFunctions::base64UrlSafeEncode(
                                hash('sha256', $keyAuthorization, true)
                            );
                            $authorizations[] = [
                                'type' => LEOrder::CHALLENGE_TYPE_DNS,
                                'identifier' => $auth->identifier['value'],
                                'DNSDigest' => $DNSDigest
                            ];
                            break;
                    }
                }
            }
        }

        return count($authorizations) > 0 ? $authorizations : false;
    }

    /**
     * Sends a verification request for a given $identifier and $type. The function itself checks whether the
     * verification is valid before making the request.
     * Updates the LetsEncrypt Authorization instances after a successful verification.
     *
     * @param string $identifier The domain name to verify.
     * @param int $type The type of verification. Supporting LEOrder::CHALLENGE_TYPE_HTTP and
     *                           LEOrder::CHALLENGE_TYPE_DNS.
     *
     * @return boolean  Returns true when the verification request was successful, false if not.
     */
    public function verifyPendingOrderAuthorization($identifier, $type)
    {
        $privateKey = $this->loadAccountKey();
        $details = openssl_pkey_get_details($privateKey);

        $header = [
            "e" => LEFunctions::base64UrlSafeEncode($details["rsa"]["e"]),
            "kty" => "RSA",
            "n" => LEFunctions::base64UrlSafeEncode($details["rsa"]["n"])
        ];
        $digest = LEFunctions::base64UrlSafeEncode(hash('sha256', json_encode($header), true));

        foreach ($this->authorizations as $auth) {
            if ($auth->identifier['value'] == $identifier) {
                if ($auth->status == 'pending') {
                    $challenge = $auth->getChallenge($type);
                    if ($challenge['status'] == 'pending') {
                        $keyAuthorization = $challenge['token'] . '.' . $digest;
                        switch ($type) {
                            case LEOrder::CHALLENGE_TYPE_HTTP:
                                return $this->verifyHTTPChallenge($identifier, $challenge, $keyAuthorization, $auth);
                            case LEOrder::CHALLENGE_TYPE_DNS:
                                return $this->verifyDNSChallenge($identifier, $challenge, $keyAuthorization, $auth);
                        }
                    }
                }
            }
        }
        return false;
    }

    private function verifyDNSChallenge($identifier, array $challenge, $keyAuthorization, LEAuthorization $auth)
    {
        //check it ourselves
        $DNSDigest = LEFunctions::base64UrlSafeEncode(hash('sha256', $keyAuthorization, true));
        if (!$this->dns->checkChallenge($identifier, $DNSDigest)) {
            $this->log->warning("DNS challenge for $identifier tested, found invalid.");
            return false;
        }

        //ask LE to check
        $sign = $this->connector->signRequestKid(
            ['keyAuthorization' => $keyAuthorization],
            $this->connector->accountURL,
            $challenge['url']
        );
        $post = $this->connector->post($challenge['url'], $sign);
        if ($post['status'] !== 200) {
            $this->log->warning("DNS challenge for $identifier valid, but failed to post to ACME service");
            return false;
        }

        while ($auth->status == 'pending') {
            $this->log->notice("DNS challenge for $identifier valid - waiting for confirmation");
            $this->sleep->for(1);
            $auth->updateData();
        }
        $this->log->notice("DNS challenge for $identifier validated");

        return true;
    }

    private function verifyHTTPChallenge($identifier, array $challenge, $keyAuthorization, LEAuthorization $auth)
    {
        if (!LEFunctions::checkHTTPChallenge($identifier, $challenge['token'], $keyAuthorization)) {
            $this->log->warning("HTTP challenge for $identifier tested, found invalid.");
            return false;
        }

        $sign = $this->connector->signRequestKid(
            ['keyAuthorization' => $keyAuthorization],
            $this->connector->accountURL,
            $challenge['url']
        );

        $post = $this->connector->post($challenge['url'], $sign);
        if ($post['status'] !== 200) {
            $this->log->warning("HTTP challenge for $identifier valid, but failed to post to ACME service");
            return false;
        }

        while ($auth->status == 'pending') {
            $this->log->notice("HTTP challenge for $identifier valid - waiting for confirmation");
            $this->sleep->for(1);
            $auth->updateData();
        }
        $this->log->notice("HTTP challenge for $identifier validated");
        return true;
    }

    /**
     * Deactivate an LetsEncrypt Authorization instance.
     *
     * @param string $identifier The domain name for which the verification should be deactivated.
     *
     * @return boolean  Returns true is the deactivation request was successful, false if not.
     */
    public function deactivateOrderAuthorization($identifier)
    {
        foreach ($this->authorizations as $auth) {
            if ($auth->identifier['value'] == $identifier) {
                $sign = $this->connector->signRequestKid(
                    ['status' => 'deactivated'],
                    $this->connector->accountURL,
                    $auth->authorizationURL
                );
                $post = $this->connector->post($auth->authorizationURL, $sign);
                if (strpos($post['header'], "200 OK") !== false) {
                    $this->log->info('Authorization for \'' . $identifier . '\' deactivated.');
                    $this->updateAuthorizations();
                    return true;
                }
            }
        }

        $this->log->warning('No authorization found for \'' . $identifier . '\', cannot deactivate.');

        return false;
    }

    /**
     * Generates a Certificate Signing Request for the identifiers in the current LetsEncrypt Order instance.
     * If possible, the base name will be the certificate common name and all domain names in this LetsEncrypt Order
     * instance will be added to the Subject Alternative Names entry.
     *
     * @return string   Returns the generated CSR as string, unprepared for LetsEncrypt. Preparation for the request
     *                  happens in finalizeOrder()
     */
    public function generateCSR()
    {
        $domains = array_map(function ($dns) {
            return $dns['value'];
        }, $this->identifiers);

        $dn = ["commonName" => $this->calcCommonName($domains)];

        $san = implode(",", array_map(function ($dns) {
            return "DNS:" . $dns;
        }, $domains));
        $tmpConf = tmpfile();
        if ($tmpConf === false) {
            //@codeCoverageIgnoreStart
            throw new RuntimeException('LEOrder::generateCSR failed to create tmp file');
            //@codeCoverageIgnoreEnd
        }
        $tmpConfMeta = stream_get_meta_data($tmpConf);
        $tmpConfPath = $tmpConfMeta["uri"];

        fwrite(
            $tmpConf,
            'HOME = .
			RANDFILE = $ENV::HOME/.rnd
			[ req ]
			default_bits = 4096
			default_keyfile = privkey.pem
			distinguished_name = req_distinguished_name
			req_extensions = v3_req
			[ req_distinguished_name ]
			countryName = Country Name (2 letter code)
			[ v3_req ]
			basicConstraints = CA:FALSE
			subjectAltName = ' . $san . '
			keyUsage = nonRepudiation, digitalSignature, keyEncipherment'
        );

        $privateKey = $this->loadCertificateKey();
        $csr = openssl_csr_new($dn, $privateKey, ['config' => $tmpConfPath, 'digest_alg' => 'sha256']);
        openssl_csr_export($csr, $csr);
        return $csr;
    }

    private function calcCommonName($domains)
    {
        if (in_array($this->basename, $domains)) {
            $CN = $this->basename;
        } elseif (in_array('*.' . $this->basename, $domains)) {
            $CN = '*.' . $this->basename;
        } else {
            $CN = $domains[0];
        }
        return $CN;
    }
    /**
     * Checks, for redundancy, whether all authorizations are valid, and finalizes the order. Updates this LetsEncrypt
     * Order instance with the new data.
     *
     * @param string $csr The Certificate Signing Request as a string. Can be a custom CSR. If empty, a CSR will
     *                    be generated with the generateCSR() function.
     *
     * @return boolean  Returns true if the finalize request was successful, false if not.
     */
    public function finalizeOrder($csr = '')
    {
        if ($this->status == 'pending') {
            if ($this->allAuthorizationsValid()) {
                if (empty($csr)) {
                    $csr = $this->generateCSR();
                }
                if (preg_match(
                    '~-----BEGIN\sCERTIFICATE\sREQUEST-----(.*)-----END\sCERTIFICATE\sREQUEST-----~s',
                    $csr,
                    $matches
                )
                ) {
                    $csr = $matches[1];
                }
                $csr = trim(LEFunctions::base64UrlSafeEncode(base64_decode($csr)));
                $sign = $this->connector->signRequestKid(
                    ['csr' => $csr],
                    $this->connector->accountURL,
                    $this->finalizeURL
                );
                $post = $this->connector->post($this->finalizeURL, $sign);
                if (strpos($post['header'], "200 OK") !== false) {
                    $this->status = $post['body']['status'];
                    $this->expires = $post['body']['expires'];
                    $this->identifiers = $post['body']['identifiers'];
                    $this->authorizationURLs = $post['body']['authorizations'];
                    $this->finalizeURL = $post['body']['finalize'];
                    if (array_key_exists('certificate', $post['body'])) {
                        $this->certificateURL = $post['body']['certificate'];
                    }
                    $this->updateAuthorizations();
                    $this->log->info('Order for \'' . $this->basename . '\' finalized.');

                    return true;
                }
            } else {
                $this->log->warning(
                    'Not all authorizations are valid for \'' .
                    $this->basename . '\'. Cannot finalize order.'
                );
            }
        } else {
            $this->log->warning(
                'Order status for \'' . $this->basename .
                '\' is \'' . $this->status . '\'. Cannot finalize order.'
            );
        }
        return false;
    }

    /**
     * Gets whether the LetsEncrypt Order is finalized by checking whether the status is processing or valid. Keep in
     * mind, a certificate is not yet available when the status still is processing.
     *
     * @return boolean  Returns true if finalized, false if not.
     */
    public function isFinalized()
    {
        return ($this->status == 'processing' || $this->status == 'valid');
    }

    /**
     * Requests the certificate for this LetsEncrypt Order instance, after finalization. When the order status is still
     * 'processing', the order will be polled max four times with five seconds in between. If the status becomes 'valid'
     * in the meantime, the certificate will be requested. Else, the function returns false.
     *
     * @return boolean  Returns true if the certificate is stored successfully, false if the certificate could not be
     *                  retrieved or the status remained 'processing'.
     */
    public function getCertificate()
    {
        $polling = 0;
        while ($this->status == 'processing' && $polling < 4) {
            $this->log->info('Certificate for \'' . $this->basename . '\' being processed. Retrying in 5 seconds...');

            $this->sleep->for(5);
            $this->updateOrderData();
            $polling++;
        }

        if ($this->status != 'valid' || empty($this->certificateURL)) {
            $this->log->warning(
                'Order for \'' . $this->basename . '\' not valid. Cannot retrieve certificate.'
            );
            return false;
        }

        $get = $this->connector->get($this->certificateURL);
        if (strpos($get['header'], "200 OK") === false) {
            $this->log->warning(
                'Invalid response for certificate request for \'' . $this->basename .
                '\'. Cannot save certificate.'
            );
            return false;
        }

        return $this->writeCertificates($get['body']);
    }


    private function writeCertificates($body)
    {
        if (preg_match_all('~(-----BEGIN\sCERTIFICATE-----[\s\S]+?-----END\sCERTIFICATE-----)~i', $body, $matches)) {
            if (isset($this->certificateKeys['certificate'])) {
                file_put_contents($this->certificateKeys['certificate'], $matches[0][0]);
            }

            $matchCount = count($matches[0]);
            if ($matchCount > 1 && isset($this->certificateKeys['fullchain_certificate'])) {
                $fullchain = $matches[0][0] . "\n";

                for ($i = 1; $i < $matchCount; $i++) {
                    $fullchain .= $matches[0][$i] . "\n";
                }
                file_put_contents(trim($this->certificateKeys['fullchain_certificate']), $fullchain);
            }
            $this->log->info('Certificate for \'' . $this->basename . '\' saved');

            return true;
        }

        $this->log->warning(
            'Received invalid certificate for \'' . $this->basename .
            '\'. Cannot save certificate.'
        );
        return false;
    }

    /**
     * Revokes the certificate in the current LetsEncrypt Order instance, if existent. Unlike stated in the ACME draft,
     * the certificate revoke request cannot be signed with the account private key, and will be signed with the
     * certificate private key.
     *
     * @param int $reason The reason to revoke the LetsEncrypt Order instance certificate. Possible reasons can be
     *                        found in section 5.3.1 of RFC5280.
     *
     * @return boolean  Returns true if the certificate was successfully revoked, false if not.
     */
    public function revokeCertificate($reason = 0)
    {
        if ($this->status == 'valid') {
            if (isset($this->certificateKeys['certificate'])) {
                $certFile = $this->certificateKeys['certificate'];
            } elseif (isset($this->certificateKeys['fullchain_certificate'])) {
                $certFile = $this->certificateKeys['fullchain_certificate'];
            } else {
                throw new \RuntimeException(
                    'certificateKeys[certificate] or certificateKeys[fullchain_certificate] required'
                );
            }

            if (file_exists($certFile) && file_exists($this->certificateKeys['private_key'])) {
                $certificate = file_get_contents($this->certificateKeys['certificate']);
                preg_match('~-----BEGIN\sCERTIFICATE-----(.*)-----END\sCERTIFICATE-----~s', $certificate, $matches);
                $certificate = trim(LEFunctions::base64UrlSafeEncode(base64_decode(trim($matches[1]))));

                $sign = $this->connector->signRequestJWK(
                    ['certificate' => $certificate, 'reason' => $reason],
                    $this->connector->revokeCert
                );
                $post = $this->connector->post($this->connector->revokeCert, $sign);
                if (strpos($post['header'], "200 OK") !== false) {
                    $this->log->info('Certificate for order \'' . $this->basename . '\' revoked.');
                    return true;
                } else {
                    $this->log->warning('Certificate for order \'' . $this->basename . '\' cannot be revoked.');
                }
            } else {
                $this->log->warning(
                    'Certificate for order \'' . $this->basename .
                    '\' not found. Cannot revoke certificate.'
                );
            }
        } else {
            $this->log->warning(
                'Order for \'' . $this->basename .
                '\' not valid. Cannot revoke certificate.'
            );
        }
        return false;
    }
}
