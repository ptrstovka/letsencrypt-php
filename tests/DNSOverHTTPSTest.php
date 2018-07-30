<?php

namespace Elphin\PHPCertificateToolbox;

use Elphin\PHPCertificateToolbox\DNSValidator\DNSOverHTTPS;
use PHPUnit\Framework\TestCase;

class DNSOverHTTPSTest extends TestCase
{

    public function testGetGoogle()
    {
        $client = new DNSOverHTTPS(DNSOverHTTPS::DNS_GOOGLE);
        $output = $client->get('example.com', 1);
        $this->assertEquals(0, $output->Status);
    }

    public function testGetMozilla()
    {
        $client = new DNSOverHTTPS(DNSOverHTTPS::DNS_MOZILLA);
        $output = $client->get('example.com', 1);
        $this->assertEquals(0, $output->Status);
    }

    public function testGetCloudflare()
    {
        $client = new DNSOverHTTPS(DNSOverHTTPS::DNS_CLOUDFLARE);
        $output = $client->get('example.com', 1);
        $this->assertEquals(0, $output->Status);
    }
}
