<?php

namespace Elphin\LEClient;

use Elphin\LEClient\Exception\LogicException;
use Elphin\LEClient\Exception\RuntimeException;
use GuzzleHttp\Client;
use GuzzleHttp\Exception\RequestException;
use GuzzleHttp\Exception\TransferException;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Request;

class LEConnectorTest extends LETestCase
{
    private function prepareKeysArray($subdir = 'le-client-test')
    {
        $keys=sys_get_temp_dir().'/'.$subdir;
        $this->deleteDirectory($keys);
        mkdir($keys);

        $keys = [
            "private_key" => "$keys/le-connector-test-private.pem",
            "public_key" => "$keys/le-connector-test-public.pem"
        ];

        return $keys;
    }

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
        $keys = $this->prepareKeysArray();

        $connector = new LEConnector($logger, $client, 'https://acme-staging-v02.api.letsencrypt.org', $keys);

        //it's enough to reach here without getting any exceptions
        $this->assertNotNull($connector);
    }


    /**
     * @expectedException RuntimeException
     */
    public function testBadRequest()
    {
        $logger=new DiagnosticLogger();

        // when the LEConnector is constructed, it requests the directory and get a new nonce, so
        // we set that up here
        $mock = new MockHandler([
            $this->getMissingResponse(),
            new RequestException("Unexpected request", new Request('GET', 'test'))
        ]);

        $handler = HandlerStack::create($mock);
        $client = new Client(['handler' => $handler]);
        $keys = $this->prepareKeysArray();

        new LEConnector($logger, $client, 'https://acme-staging-v02.api.letsencrypt.org', $keys);
    }

    /**
     * @expectedException LogicException
     */
    public function testDeactivated()
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
        $keys = $this->prepareKeysArray();


        $connector = new LEConnector($logger, $client, 'https://acme-staging-v02.api.letsencrypt.org', $keys);

        //deactivation isn't persisted, its just a flag to prevent further API calls in the same session
        $connector->accountDeactivated = true;

        $connector->get("https://acme-staging-v02.api.letsencrypt.org/acme/new-acct");
    }

    /**
     * Just for coverage, this checks that if guzzle throws some kind of internal failure, we
     * in turn throw a RuntimeException
     * @expectedException RuntimeException
     */
    public function testGuzzleException()
    {
        $logger=new DiagnosticLogger();
        $mock = new MockHandler([
            new TransferException("Guzzle failure")
        ]);

        $handler = HandlerStack::create($mock);
        $client = new Client(['handler' => $handler]);
        $keys = $this->prepareKeysArray();


        new LEConnector($logger, $client, 'https://acme-staging-v02.api.letsencrypt.org', $keys);
    }

    public function testSignRequestJWK()
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
        $keys = $this->prepareKeysArray();

        //build some keys
        LEFunctions::RSAgenerateKeys(null, $keys['private_key'], $keys['public_key'], 2048);

        $connector = new LEConnector($logger, $client, 'https://acme-staging-v02.api.letsencrypt.org', $keys);

        $json = $connector->signRequestJWK(['test'=>'foo'], 'http://example.org');
        $data = json_decode($json, true);
        $this->assertArrayHasKey('protected', $data);
        $this->assertArrayHasKey('payload', $data);
        $this->assertArrayHasKey('signature', $data);
    }

    public function testSignRequestKid()
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
        $keys = $this->prepareKeysArray();

        //build some keys
        LEFunctions::RSAgenerateKeys(null, $keys['private_key'], $keys['public_key'], 2048);

        $connector = new LEConnector($logger, $client, 'https://acme-staging-v02.api.letsencrypt.org', $keys);

        $json = $connector->signRequestKid(['test'=>'foo'], '1234', 'http://example.org');
        $data = json_decode($json, true);
        $this->assertArrayHasKey('protected', $data);
        $this->assertArrayHasKey('payload', $data);
        $this->assertArrayHasKey('signature', $data);
    }
}
