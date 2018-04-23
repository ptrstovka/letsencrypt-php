<?php

namespace Elphin\PHPCertificateToolbox;

use Elphin\PHPCertificateToolbox\Exception\LogicException;
use PHPUnit\Framework\TestCase;

class LEFunctionsTest extends TestCase
{
    public function testRSAGenerateKeys()
    {
        $keys = LEFunctions::RSAGenerateKeys();

        $this->assertArrayHasKey('public', $keys);
        $this->assertArrayHasKey('private', $keys);
        $this->assertContains('BEGIN PUBLIC KEY', $keys['public']);
        $this->assertContains('BEGIN PRIVATE KEY', $keys['private']);
    }

    /**
     * @expectedException LogicException
     */
    public function testRSAGenerateKeysWithInvalidLength()
    {
        LEFunctions::RSAGenerateKeys(111);
    }

    /**
     * @dataProvider ecKeyLengthProvider
     */
    public function testECGenerateKeys($length)
    {
        $keys = LEFunctions::ECGenerateKeys($length);

        $this->assertArrayHasKey('public', $keys);
        $this->assertArrayHasKey('private', $keys);
        $this->assertContains('BEGIN PUBLIC KEY', $keys['public']);
        $this->assertContains('BEGIN EC PRIVATE KEY', $keys['private']);
    }

    public function ecKeyLengthProvider()
    {
        return [[256], [384]];
    }

    /**
     * @expectedException LogicException
     */
    public function testECGenerateKeysWithInvalidLength()
    {
        LEFunctions::ECGenerateKeys(111);
    }


    public function testBase64()
    {
        $encoded = LEFunctions::base64UrlSafeEncode('frumious~bandersnatch!');
        $this->assertEquals('ZnJ1bWlvdXN-YmFuZGVyc25hdGNoIQ', $encoded);

        $plain = LEFunctions::base64UrlSafeDecode($encoded);
        $this->assertEquals('frumious~bandersnatch!', $plain);
    }

    private function rm($file)
    {
        if (file_exists($file)) {
            unlink($file);
        }
    }
}
