<?php

namespace Elphin\LEClient;

use GuzzleHttp\Client;
use GuzzleHttp\Exception\RequestException;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Request;

class LEConnectorTest extends LETestCase
{
    public function testConstructor()
    {
        $logger=new DiagnosticLogger();

        // when the LEConnector is constructed, it requests the directory and get a new nonce, so
        // we set that up here
        $mock = new MockHandler([
            $this->getDirectoryResponse(),
            $this->headNewNonceResponse(),
            new RequestException("Unexpected request", new Request('GET', 'test'))
        ]);

        $handler = HandlerStack::create($mock);
        $client = new Client(['handler' => $handler]);

        $keys=sys_get_temp_dir().'/le-client-test';
        $this->deleteDirectory($keys);

        $keys = [
            "private_key" => "$keys/le-connector-test-private.pem",
            "public_key" => "$keys/le-connector-test-public.pem"
        ];

        $connector = new LEConnector($logger, $client, 'https://acme-staging-v02.api.letsencrypt.org', $keys);

        //it's enough to reach here without getting any exceptions
        $this->assertNotNull($connector);
    }
}
