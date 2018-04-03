<?php

namespace Elphin\LEClient;

use Elphin\LEClient\Exception\RuntimeException;
use Prophecy\Argument;
use Psr\Log\NullLogger;

/**
 * Tests LEAccount - because this was retrofitted to a class not really designed for testing, this
 * is a litle scrappy at present...
 *
 * @package Elphin\LEClient
 */
class LEAccountTest extends LETestCase
{
    /**
     * @return LEConnector
     */
    private function mockConnector()
    {
        $connector = $this->prophesize(LEConnector::class);
        $connector->newAccount = 'http://test.local/new-account';
        $connector->keyChange = 'http://test.local/change-key';

        $connector->signRequestKid(Argument::any(), Argument::any(), Argument::any())
            ->willReturn(json_encode(['protected'=>'','payload'=>'','signature'=>'']));
        $connector->signRequestJWK(Argument::any(), Argument::any(), Argument::any())
            ->willReturn(json_encode(['protected'=>'','payload'=>'','signature'=>'']));

        $accountUrl='https://acme-staging-v02.api.letsencrypt.org/acme/acct/5757881';
        $newaccount=[];
        $newaccount['header']='201 Created\r\nLocation: '.$accountUrl;
        $newaccount['body']=json_decode($this->postNewAccountJSON(), true);
        $newaccount['status']=201;

        $connector->post('http://test.local/new-account', Argument::any())
            ->willReturn($newaccount);

        $account=$newaccount;
        $account['header']='200 OK\r\nLocation: '.$accountUrl;
        $account['status']=200;
        $connector->post($accountUrl, Argument::any())
            ->willReturn($account);

        $connector->post('http://test.local/new-account2', Argument::any())
            ->willReturn($account);

        $account['header']='404 Not Found';
        $account['status']=404;
        $connector->post('http://test.local/new-account3', Argument::any())
            ->willReturn($account);

        $account=$newaccount;
        $account['header']='200 OK\r\n';
        $account['status']=200;
        $connector->post($connector->keyChange, Argument::any())
            ->willReturn($account);

        return $connector->reveal();
    }

    protected function initCertFiles()
    {
        $keyDir=sys_get_temp_dir().'/le-acc-test';
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
        $files = $this->initCertFiles();

        //at first, should not exist
        $this->assertFileNotExists($files['public_key']);
        $this->assertFileNotExists($files['private_key']);

        new LEAccount($conn, $log, ['test@example.org'], $files);

        $this->assertFileExists($files['public_key']);
        $this->assertFileExists($files['private_key']);

        //reload for coverage...we need to fudge the mock connection a little
        $conn->newAccount = 'http://test.local/new-account2';

        new LEAccount($conn, $log, ['test@example.org'], $files);

        //it's enough to reach here without exception
        $this->assertTrue(true);
    }

    /**
     * @expectedException RuntimeException
     */
    public function testNotFound()
    {
        $conn = $this->mockConnector();
        $log = new NullLogger();
        $files = $this->initCertFiles();

        //at first, should not exist
        $this->assertFileNotExists($files['public_key']);
        $this->assertFileNotExists($files['private_key']);

        new LEAccount($conn, $log, ['test@example.org'], $files);

        $this->assertFileExists($files['public_key']);
        $this->assertFileExists($files['private_key']);

        //when we reload, we fudge things to get a 404
        $conn->newAccount = 'http://test.local/new-account3';

        new LEAccount($conn, $log, ['test@example.org'], $files);
    }

    public function testUpdateAccount()
    {
        $conn = $this->mockConnector();
        $log = new NullLogger();
        $files = $this->initCertFiles();

        $account = new LEAccount($conn, $log, ['test@example.org'], $files);

        $ok = $account->updateAccount(['new@example.org']);
        $this->assertTrue($ok);
    }

    public function testChangeKeys()
    {
        $conn = $this->mockConnector();
        $log = new NullLogger();
        $files = $this->initCertFiles();

        $account = new LEAccount($conn, $log, ['test@example.org'], $files);

        $ok = $account->changeAccountKeys();
        $this->assertTrue($ok);
    }

    public function testDeactivate()
    {
        $conn = $this->mockConnector();
        $log = new NullLogger();
        $files = $this->initCertFiles();

        $account = new LEAccount($conn, $log, ['test@example.org'], $files);

        $ok = $account->deactivateAccount();
        $this->assertTrue($ok);
    }
}
