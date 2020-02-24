<?php

namespace Elphin\PHPCertificateToolbox;

/**
 * In real world use, we want to sleep in between various actions. For testing, not so much.
 * So, we make it possible to inject a less sleepy service for testing
 *
 * @codeCoverageIgnore
 */
class Sleep implements WaitInterface
{
    public function for($seconds)
    {
        sleep($seconds);
    }
}
