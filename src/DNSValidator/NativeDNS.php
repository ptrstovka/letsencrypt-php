<?php

namespace Elphin\LEClient;

use Elphin\LEClient\DNS\DNSInterface;

/**
 * Class DNS exists to provide an injectable service for DNS queries which we can mock for unit tests
 * @package Elphin\LEClient
 * @codeCoverageIgnore
 */
class NativeDNS implements DNSInterface
{
    public function checkChallenge($domain, $requiredDigest) : bool
    {
        $hostname = '_acme-challenge.' . str_replace('*.', '', $domain);
        $records =  dns_get_record($hostname, DNS_TXT);
        foreach ($records as $record) {
            if ($record['host'] == $hostname && $record['type'] == 'TXT' && $record['txt'] == $requiredDigest) {
                return true;
            }
        }
        return false;
    }
}
