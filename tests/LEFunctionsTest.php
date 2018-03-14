<?php

namespace Elphin\LEClient;

use Elphin\LEClient\Exception\LogicException;
use PHPUnit\Framework\TestCase;

class LEFunctionsTest extends TestCase
{
    public function testRSAGenerateKeys()
    {
        $tmp = sys_get_temp_dir() . DIRECTORY_SEPARATOR;
        $this->rm($tmp . 'private.pem');
        $this->rm($tmp . 'public.pem');

        LEFunctions::RSAGenerateKeys($tmp);

        //check we have some keys
        $this->assertFileExists($tmp . 'private.pem');
        $this->assertFileExists($tmp . 'public.pem');

        //cleanup
        $this->rm($tmp . 'private.pem');
        $this->rm($tmp . 'public.pem');
    }

    /**
     * @expectedException LogicException
     */
    public function testRSAGenerateKeysWithInvalidLength()
    {
        $tmp = sys_get_temp_dir() . DIRECTORY_SEPARATOR;
        LEFunctions::RSAGenerateKeys($tmp, 'private.pem', 'public.pem', 111);
    }

    /**
     * @dataProvider ecKeyLengthProvider
     */
    public function testECGenerateKeys($length)
    {
        $tmp = sys_get_temp_dir() . DIRECTORY_SEPARATOR;
        $this->rm($tmp . 'private.pem');
        $this->rm($tmp . 'public.pem');

        LEFunctions::ECGenerateKeys($tmp, 'private.pem', 'public.pem', $length);

        //check we have some keys
        $this->assertFileExists($tmp . 'private.pem');
        $this->assertFileExists($tmp . 'public.pem');

        //cleanup
        $this->rm($tmp . 'private.pem');
        $this->rm($tmp . 'public.pem');
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
        $tmp = sys_get_temp_dir() . DIRECTORY_SEPARATOR;
        LEFunctions::ECGenerateKeys($tmp, 'private.pem', 'public.pem', 111);
    }


    public function testBase64()
    {
        $encoded = LEFunctions::base64UrlSafeEncode('frumious~bandersnatch!');
        $this->assertEquals('ZnJ1bWlvdXN-YmFuZGVyc25hdGNoIQ', $encoded);

        $plain = LEFunctions::base64UrlSafeDecode($encoded);
        $this->assertEquals('frumious~bandersnatch!', $plain);
    }

    public function testCreateHTAccess()
    {
        $tmp = sys_get_temp_dir() . DIRECTORY_SEPARATOR;
        $this->rm($tmp . '.htaccess');
        LEFunctions::createhtaccess($tmp);
        $this->assertFileExists($tmp . '.htaccess');
        $this->rm($tmp . '.htaccess');
    }

    private function rm($file)
    {
        if (file_exists($file)) {
            unlink($file);
        }
    }
}
