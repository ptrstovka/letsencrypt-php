<?php

namespace Elphin\LEClient;

/**
 * Class DNS exists to provide an injectable service for DNS queries which we can mock for unit tests
 * @package Elphin\LEClient
 * @codeCoverageIgnore
 */
class DNS
{
    public function checkChallenge($domain, $requiredDigest)
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
