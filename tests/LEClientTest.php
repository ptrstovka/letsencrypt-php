<?php

namespace Elphin\LEClient;

use Elphin\LEClient\Exception\LogicException;
use GuzzleHttp\Client;
use GuzzleHttp\Exception\RequestException;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Request;
use Prophecy\Argument;

/**
 * This is more of an integration test than a unit test - we mock the actual HTTP requests, but
 * the client still interacts with other components
 *
 * @package Elphin\LEClient
 */
class LEClientTest extends LETestCase
{
    public function testCertificationWithDNS()
    {
        $logger = new DiagnosticLogger();

        $mock = new MockHandler([
            //initial construction of connector
            $this->getDirectoryResponse(),
            $this->headNewNonceResponse(),

            //getAccount
            $this->postNewAccountResponse(),
            $this->postAccountResponse(),

            //getOrCreateOrder
            $this->postNewOrderResponse(),
            $this->getAuthzResponse('example.org', false),
            $this->getAuthzResponse('test.example.org', false),

            //verifyPendingOrderAuthorization
            $this->postChallengeResponse(),
            $this->getAuthzResponse('example.org', true),
            $this->postChallengeResponse(),
            $this->getAuthzResponse('test.example.org', true),

            //finalizeOrder
            $this->getPostFinalizeResponse(),
            $this->getAuthzResponse('example.org', true),

            //getCertificate
            $this->getCertResponse(),

            new RequestException("Unexpected request", new Request('GET', 'test'))
        ]);

        //mock DNS service which will pretend our challenges have been set
        $dns = $this->prophesize(DNS::class);
        $dns->checkChallenge('example.org', Argument::any())
            ->willReturn(true);
        $dns->checkChallenge('test.example.org', Argument::any())
            ->willReturn(true);

        //mock sleep service which, erm, won't sleep. Shave a few seconds off tests!
        $sleep = $this->prophesize(Sleep::class);
        $sleep->for(Argument::any())->willReturn(true);

        $handler = HandlerStack::create($mock);
        $httpClient = new Client(['handler' => $handler]);

        $keys = sys_get_temp_dir() . '/le-client-test';
        $this->deleteDirectory($keys);
        $client = new LEClient(['test@example.com'], LEClient::LE_STAGING, $logger, $httpClient, $keys);

        //use our DNS and Sleep mocks
        $client->setDNS($dns->reveal());
        $client->setSleep($sleep->reveal());

        // Defining the base name for this order
        $basename = 'example.org';
        $domains = ['example.org', 'test.example.org'];

        $order = $client->getOrCreateOrder($basename, $domains);

        //now let's simulate checking a DNS challenge
        if (!$order->allAuthorizationsValid()) {
            // Get the DNS challenges from the pending authorizations.
            $pending = $order->getPendingAuthorizations(LEOrder::CHALLENGE_TYPE_DNS);
            // Walk the list of pending authorization DNS challenges.
            if (!empty($pending)) {
                foreach ($pending as $challenge) {
                    //now verify the DNS challenage has been fulfilled
                    $verified = $order->verifyPendingOrderAuthorization(
                        $challenge['identifier'],
                        LEOrder::CHALLENGE_TYPE_DNS
                    );
                    $this->assertTrue($verified);
                }
            }
        }

        // at this point, we've simulated that the DNS has been validated
        $this->assertTrue($order->allAuthorizationsValid());

        //but the order is not yet finalized
        $this->assertFalse($order->isFinalized());

        //so let's do it!
        $order->finalizeOrder();

        //should be good now
        $this->assertTrue($order->isFinalized());

        //finally, we can get our cert
        $order->getCertificate();

        //one final test for coverage - get the acount
        $account = $client->getAccount();
        $this->assertInstanceOf(LEAccount::class, $account);
    }

    public function testBooleanBaseUrl()
    {
        $logger = new DiagnosticLogger();
        $http = $this->prophesize(Client::class);
        $keys = sys_get_temp_dir() . '/le-client-test';

        //this should give us a staging url
        $client = new LEClient(['test@example.com'], true, $logger, $http->reveal(), $keys);
        $this->assertEquals(LEClient::LE_STAGING, $client->getBaseUrl());

        //and this should be production
        $client = new LEClient(['test@example.com'], false, $logger, $http->reveal(), $keys);
        $this->assertEquals(LEClient::LE_PRODUCTION, $client->getBaseUrl());
    }

    /**
     * @expectedException LogicException
     */
    public function testInvalidBaseUrl()
    {
        $logger = new DiagnosticLogger();
        $http = $this->prophesize(Client::class);
        $keys = sys_get_temp_dir() . '/le-client-test';

        //this should give us a staging url
        new LEClient(['test@example.com'], [], $logger, $http->reveal(), $keys);
    }

    public function testArrayKey()
    {
        $logger = new DiagnosticLogger();
        $http = $this->prophesize(Client::class);

        $dir = sys_get_temp_dir() . '/le-client-test';
        $this->deleteDirectory($dir);
        mkdir($dir);

        //this should give us a staging url
        $keys = [
            "public_key" => $dir . '/public.pem',
            "private_key" => $dir . '/private.pem',
            "certificate" => $dir . '/certificate.crt',
            "fullchain_certificate" => $dir . '/fullchain.crt',
            "order" => $dir . '/order'
        ];

        $accdir = $dir . "/acc";
        mkdir($accdir);

        $account = [
            "private_key" => $accdir . '/private.pem',
            "public_key" => $accdir . '/public.pem'
        ];

        $client = new LEClient(['test@example.com'], true, $logger, $http->reveal(), $keys, $account);
        //it's enough to reach here without exceptions
        $this->assertNotNull($client);
    }

    /**
     * @dataProvider invalidKeySetups
     * @expectedException LogicException
     */
    public function testInvalidKeySetups($keys, $account)
    {
        $logger = new DiagnosticLogger();
        $http = $this->prophesize(Client::class);
        new LEClient(['test@example.com'], true, $logger, $http->reveal(), $keys, $account);
    }

    /**
     * This provides a variety of bad setups, all of which should throw a logic exception
     * @return array
     */
    public function invalidKeySetups()
    {
        $dir = sys_get_temp_dir() . '/le-client-test';
        $this->deleteDirectory($dir);
        mkdir($dir);

        $accdir = $dir . "/acc";
        mkdir($accdir);

        return [
            //test that keys and account settings must be both strings or both arrays
            [[], ''],
            ['', []],
            [new \stdClass(), new \stdClass()],

            //array has no certificate
            [[], []],

            //no private key
            [['certificate' => '', 'fullchain_certificate'=>''], []],

            [['certificate' => '', 'fullchain_certificate'=>'', 'private_key' => ''], []],

            //good cert, bad acc missing private_key
            [
                [
                    'certificate' => $dir . '/certificate.crt',
                    'fullchain_certificate'=>$dir . '/fullchain.crt',
                    'private_key' => $dir . '/private.pem',
                    'public_key' => $dir . '/public.pem',
                    'order' => $dir . '/order'
                ],
                []
            ],

            //good cert, acc missing public_key
            [
                [
                    'certificate' => $dir . '/certificate.crt',
                    'fullchain_certificate'=>$dir . '/fullchain.crt',
                    'private_key' => $dir . '/private.pem',
                    'public_key' => $dir . '/public.pem',
                    'order' => $dir . '/order'
                ],
                [
                    'private_key' => $accdir . '/private.pem',
                ]
            ]

        ];
    }
}
