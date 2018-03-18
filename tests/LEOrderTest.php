<?php

namespace Elphin\LEClient;

use Elphin\LEClient\Exception\LogicException;
use Prophecy\Argument;
use Psr\Log\NullLogger;

class LEOrderTest extends LETestCase
{
    /**
     * @return LEConnector
     */
    private function mockConnector($valid = false)
    {
        $connector = $this->prophesize(LEConnector::class);
        $connector->newOrder = 'http://test.local/new-order';

        $connector->signRequestKid(Argument::any(), Argument::any(), Argument::any())
            ->willReturn(json_encode(['protected'=>'','payload'=>'','signature'=>'']));

        $neworder=[];
        $neworder['header']='201 Created\r\nLocation: http://test.local/order/test';
        $neworder['body']=json_decode($this->getOrderJSON($valid), true);

        $connector->post('http://test.local/new-order', Argument::any())
            ->willReturn($neworder);

        $authz1=[];
        $authz1['header']='200 OK';
        $authz1['body']=json_decode($this->getAuthzJSON('example.org', $valid), true);
        $connector->get(
            'https://acme-staging-v02.api.letsencrypt.org/acme/authz/X2QaFXwrBz7VlN6zdKgm_jmiBctwVZgMZXks4YhfPng',
            Argument::any()
        )->willReturn($authz1);

        $authz2=[];
        $authz2['header']='200 OK';
        $authz2['body']=json_decode($this->getAuthzJSON('test.example.org', $valid), true);
        $connector->get(
            'https://acme-staging-v02.api.letsencrypt.org/acme/authz/WDMI8oX6avFT_rEBfh-ZBMdZs3S-7li2l5gRrps4MXM',
            Argument::any()
        )->willReturn($authz2);

        $orderReq=[];
        $orderReq['header']='200 OK';
        $orderReq['body']=json_decode($this->getOrderJSON($valid), true);
        $connector->get("http://test.local/order/test")->willReturn($orderReq);

        return $connector->reveal();
    }

    protected function initCertFiles()
    {
        $keyDir=sys_get_temp_dir().'/le-order-test';
        $this->deleteDirectory($keyDir);

        $files = [
            "public_key" => $keyDir . '/public.pem',
            "private_key" => $keyDir . '/private.pem',
            "certificate" => $keyDir . '/certificate.crt',
            "fullchain_certificate" => $keyDir . '/fullchain.crt',
            "order" => $keyDir . '/order'
        ];

        mkdir($keyDir);
        return $files;
    }

    public function testBasicCreateAndReload()
    {
        $conn = $this->mockConnector();
        $log = new NullLogger();
        $dns = $this->mockDNS(true);
        $sleep = $this->mockSleep();
        $files = $this->initCertFiles();
        $basename='example.org';
        $domains = ['example.org', 'test.example.org'];
        $keyType = 'rsa-4096';
        $notBefore = '';
        $notAfter = '';

        $this->assertFileNotExists($files['public_key']);

        //this should create a new order
        $order = new LEOrder($conn, $log, $dns, $sleep);
        $order->loadOrder($files, $basename, $domains, $keyType, $notBefore, $notAfter);

        $this->assertFileExists($files['public_key']);

        //if we construct again, it should load the existing order
        $order = new LEOrder($conn, $log, $dns, $sleep);
        $order->loadOrder($files, $basename, $domains, $keyType, $notBefore, $notAfter);

        //it's enough to reach here without getting any exceptions
        $this->assertNotNull($order);
    }

    public function testCreateWithValidatedOrder()
    {
        //our connector will return an order with a certificate url
        $conn = $this->mockConnector(true);
        $log = new NullLogger();
        $dns = $this->mockDNS(true);
        $sleep = $this->mockSleep();
        $files = $this->initCertFiles();
        $basename='example.org';
        $domains = ['example.org', 'test.example.org'];
        $keyType = 'rsa-4096';
        $notBefore = '';
        $notAfter = '';

        $this->assertFileNotExists($files['public_key']);

        //this should create a new order
        $order = new LEOrder($conn, $log, $dns, $sleep);
        $order->loadOrder($files, $basename, $domains, $keyType, $notBefore, $notAfter);

        //and reload the validated order for coverage!
        $order = new LEOrder($conn, $log, $dns, $sleep);
        $order->loadOrder($files, $basename, $domains, $keyType, $notBefore, $notAfter);

        //it's enough to reach here without getting any exceptions
        $this->assertNotNull($order);
    }

    public function testMismatchedReload()
    {
        $conn = $this->mockConnector();
        $log = new NullLogger();
        $dns = $this->mockDNS(true);
        $sleep = $this->mockSleep();
        $files = $this->initCertFiles();
        $basename='example.org';
        $domains = ['example.org', 'test.example.org'];
        $keyType = 'rsa-4096';
        $notBefore = '';
        $notAfter = '';

        $this->assertFileNotExists($files['public_key']);

        //this should create a new order
        $order = new LEOrder($conn, $log, $dns, $sleep);
        $order->loadOrder($files, $basename, $domains, $keyType, $notBefore, $notAfter);

        $this->assertFileExists($files['public_key']);

        //we construct again to get a reload, but with different domains
        $domains = ['example.com', 'test.example.com'];
        $order = new LEOrder($conn, $log, $dns, $sleep);
        $order->loadOrder($files, $basename, $domains, $keyType, $notBefore, $notAfter);


        //this is allowed - we will just create a new order for the given domains, so it's enough to reach
        //here without exception
        $this->assertNotNull($order);
    }


    /**
     * @expectedException LogicException
     */
    public function testCreateWithBadWildcard()
    {
        $conn = $this->mockConnector();
        $log = new NullLogger();
        $dns = $this->mockDNS(true);
        $sleep = $this->mockSleep();
        $files = $this->initCertFiles();
        $basename='example.org';
        $domains = ['*.*.example.org'];
        $keyType = 'rsa-4096';
        $notBefore = '';
        $notAfter = '';

        $order = new LEOrder($conn, $log, $dns, $sleep);
        $order->loadOrder($files, $basename, $domains, $keyType, $notBefore, $notAfter);

    }

    /**
     * @expectedException LogicException
     */
    public function testCreateWithBadKeyType()
    {
        $conn = $this->mockConnector();
        $log = new NullLogger();
        $dns = $this->mockDNS(true);
        $sleep = $this->mockSleep();
        $files = $this->initCertFiles();
        $basename='example.org';
        $domains = ['example.org'];
        $keyType = 'wibble-4096';
        $notBefore = '';
        $notAfter = '';

        $order = new LEOrder($conn, $log, $dns, $sleep);
        $order->loadOrder($files, $basename, $domains, $keyType, $notBefore, $notAfter);

    }

    /**
     * @expectedException LogicException
     */
    public function testCreateWithBadDates()
    {
        $conn = $this->mockConnector();
        $log = new NullLogger();
        $dns = $this->mockDNS(true);
        $sleep = $this->mockSleep();
        $files = $this->initCertFiles();
        $basename='example.org';
        $domains = ['example.org'];
        $keyType = 'rsa';
        $notBefore = 'Hippopotamus';
        $notAfter = 'Primrose';

        $order = new LEOrder($conn, $log, $dns, $sleep);
        $order->loadOrder($files, $basename, $domains, $keyType, $notBefore, $notAfter);

    }

    public function testCreateWithEC()
    {
        $conn = $this->mockConnector();
        $log = new NullLogger();
        $dns = $this->mockDNS(true);
        $sleep = $this->mockSleep();
        $files = $this->initCertFiles();
        $basename='example.org';
        $domains = ['example.org', 'test.example.org'];
        $keyType = 'ec';
        $notBefore = '';
        $notAfter = '';

        $this->assertFileNotExists($files['public_key']);

        //this should create a new order
        $order = new LEOrder($conn, $log, $dns, $sleep);
        $order->loadOrder($files, $basename, $domains, $keyType, $notBefore, $notAfter);

        $this->assertFileExists($files['public_key']);
    }

    /**
     * @return LEConnector
     */
    private function mockConnectorWithNoAuths($valid = false)
    {
        $connector = $this->prophesize(LEConnector::class);
        $connector->newOrder = 'http://test.local/new-order';

        $connector->signRequestKid(Argument::any(), Argument::any(), Argument::any())
            ->willReturn(json_encode(['protected'=>'','payload'=>'','signature'=>'']));

        $order = json_decode($this->getOrderJSON($valid), true);
        $order['authorizations'] = [];

        $neworder=[];
        $neworder['header']='201 Created\r\nLocation: http://test.local/order/test';
        $neworder['body']=$order;

        $connector->post('http://test.local/new-order', Argument::any())
            ->willReturn($neworder);

        $orderReq=[];
        $orderReq['header']='200 OK';
        $orderReq['body']=$order;
        $connector->get("http://test.local/order/test")->willReturn($orderReq);

        return $connector->reveal();
    }

    /**
     * Covers the case where there are no authorizations in the order
     */
    public function testAllAuthorizationsValid()
    {
        $conn = $this->mockConnectorWithNoAuths();
        $log = new NullLogger();
        $dns = $this->mockDNS(true);
        $sleep = $this->mockSleep();
        $files = $this->initCertFiles();
        $basename='example.org';
        $domains = ['example.org', 'test.example.org'];
        $keyType = 'rsa';
        $notBefore = '';
        $notAfter = '';

        $this->assertFileNotExists($files['public_key']);

        //this should create a new order
        $order = new LEOrder($conn, $log, $dns, $sleep);
        $order->loadOrder($files, $basename, $domains, $keyType, $notBefore, $notAfter);

        $this->assertFalse($order->allAuthorizationsValid());
    }


    /**
     * @return LEConnector
     */
    private function mockConnectorForProcessingCert($eventuallyValid = true, $goodCertRequest = true, $garbage = false)
    {
        $valid = true;

        $connector = $this->prophesize(LEConnector::class);
        $connector->newOrder = 'http://test.local/new-order';

        $connector->signRequestKid(Argument::any(), Argument::any(), Argument::any())
            ->willReturn(json_encode(['protected'=>'','payload'=>'','signature'=>'']));

        //the new order is setup to be processing...
        $neworder=[];
        $neworder['header']='201 Created\r\nLocation: http://test.local/order/test';
        $neworder['body']=json_decode($this->getOrderJSON($valid), true);
        $neworder['body']['status'] = 'processing';

        $connector->post('http://test.local/new-order', Argument::any())
            ->willReturn($neworder);

        $authz1=[];
        $authz1['header']='200 OK';
        $authz1['body']=json_decode($this->getAuthzJSON('example.org', $valid), true);
        $connector->get(
            'https://acme-staging-v02.api.letsencrypt.org/acme/authz/X2QaFXwrBz7VlN6zdKgm_jmiBctwVZgMZXks4YhfPng',
            Argument::any()
        )->willReturn($authz1);

        $authz2=[];
        $authz2['header']='200 OK';
        $authz2['body']=json_decode($this->getAuthzJSON('test.example.org', $valid), true);
        $connector->get(
            'https://acme-staging-v02.api.letsencrypt.org/acme/authz/WDMI8oX6avFT_rEBfh-ZBMdZs3S-7li2l5gRrps4MXM',
            Argument::any()
        )->willReturn($authz2);

        //when the order is re-fetched, it's possibly valid
        $orderReq=[];
        $orderReq['header']='200 OK';
        $orderReq['body']=json_decode($this->getOrderJSON(true), true);
        if (!$eventuallyValid) {
            $orderReq['body']['status'] = 'processing';
        }
        $connector->get("http://test.local/order/test")->willReturn($orderReq);

        $certReq=[];
        $certReq['header']=$goodCertRequest ? '200 OK' : '500 Failed';
        $certReq['body']=$garbage ? 'NOT-A-CERT' : $this->getCertBody();
        $connector->get("https://acme-staging-v02.api.letsencrypt.org/acme/cert/fae09c6dcdaf7aa198092b3170c69129a490")
            ->willReturn($certReq);

        return $connector->reveal();
    }

    /**
     * Test a certificate fetch with a 'processing' loop in effect
     */
    public function testGetCertificate()
    {
        $conn = $this->mockConnectorForProcessingCert(true);
        $log = new NullLogger();
        $dns = $this->mockDNS(true);
        $sleep = $this->mockSleep();
        $files = $this->initCertFiles();
        $basename='example.org';
        $domains = ['example.org', 'test.example.org'];
        $keyType = 'ec';
        $notBefore = '';
        $notAfter = '';

        $this->assertFileNotExists($files['public_key']);

        //this should create a new order
        $order = new LEOrder($conn, $log, $dns, $sleep);
        $order->loadOrder($files, $basename, $domains, $keyType, $notBefore, $notAfter);

        $ok = $order->getCertificate();
        $this->assertTrue($ok);
    }

    /**
     * Test a certificate fetch with a 'processing' loop in effect
     */
    public function testGetCertificateWithValidationDelay()
    {
        $conn = $this->mockConnectorForProcessingCert(false);
        $log = new NullLogger();
        $dns = $this->mockDNS(true);
        $sleep = $this->mockSleep();
        $files = $this->initCertFiles();
        $basename='example.org';
        $domains = ['example.org', 'test.example.org'];
        $keyType = 'ec';
        $notBefore = '';
        $notAfter = '';

        $this->assertFileNotExists($files['public_key']);

        //this should create a new order
        $order = new LEOrder($conn, $log, $dns, $sleep);
        $order->loadOrder($files, $basename, $domains, $keyType, $notBefore, $notAfter);

        $ok = $order->getCertificate();
        $this->assertFalse($ok);
    }

    public function testGetCertificateWithRetrievalFailure()
    {
        $conn = $this->mockConnectorForProcessingCert(true, false);
        $log = new NullLogger();
        $dns = $this->mockDNS(true);
        $sleep = $this->mockSleep();
        $files = $this->initCertFiles();
        $basename='example.org';
        $domains = ['example.org', 'test.example.org'];
        $keyType = 'ec';
        $notBefore = '';
        $notAfter = '';

        $this->assertFileNotExists($files['public_key']);

        //this should create a new order
        $order = new LEOrder($conn, $log, $dns, $sleep);
        $order->loadOrder($files, $basename, $domains, $keyType, $notBefore, $notAfter);

        $ok = $order->getCertificate();
        $this->assertFalse($ok);
    }

    public function testGetCertificateWithGarbageRetrieval()
    {
        $conn = $this->mockConnectorForProcessingCert(true, true, true);
        $log = new NullLogger();
        $dns = $this->mockDNS(true);
        $sleep = $this->mockSleep();
        $files = $this->initCertFiles();
        $basename='example.org';
        $domains = ['example.org', 'test.example.org'];
        $keyType = 'ec';
        $notBefore = '';
        $notAfter = '';

        $this->assertFileNotExists($files['public_key']);

        //this should create a new order
        $order = new LEOrder($conn, $log, $dns, $sleep);
        $order->loadOrder($files, $basename, $domains, $keyType, $notBefore, $notAfter);

        $ok = $order->getCertificate();
        $this->assertFalse($ok);
    }
}
