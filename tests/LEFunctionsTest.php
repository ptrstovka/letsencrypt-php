<?php

namespace Elphin\LEClient;

use PHPUnit\Framework\TestCase;

class LEFunctionsTest extends TestCase
{
    /**
     * test LEFunctions::RSAGenerateKeys
     */
    public function testRSAGenerateKeys()
    {
        $tmp = sys_get_temp_dir().DIRECTORY_SEPARATOR;
        $this->rm($tmp.'private.pem');
        $this->rm($tmp.'public.pem');

        LEFunctions::RSAGenerateKeys($tmp);

        //check we have some keys
        $this->assertTrue(file_exists($tmp.'private.pem'));
        $this->assertTrue(file_exists($tmp.'public.pem'));

        //cleanup
        $this->rm($tmp.'private.pem');
        $this->rm($tmp.'public.pem');
    }

    public function testECGenerateKeys()
    {
        $tmp = sys_get_temp_dir().DIRECTORY_SEPARATOR;
        $this->rm($tmp.'private.pem');
        $this->rm($tmp.'public.pem');

        LEFunctions::ECGenerateKeys($tmp);

        //check we have some keys
        $this->assertTrue(file_exists($tmp.'private.pem'));
        $this->assertTrue(file_exists($tmp.'public.pem'));

        //cleanup
        $this->rm($tmp.'private.pem');
        $this->rm($tmp.'public.pem');
    }

    private function rm($file)
    {
        if (file_exists($file)) {
            unlink($file);
        }
    }
}
