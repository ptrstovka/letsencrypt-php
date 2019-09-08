<?php


namespace Elphin\PHPCertificateToolbox\Support;

/**
 * Helper utilities.
 * Source: https://github.com/illuminate/support/blob/master/helpers.php
 * @package Elphin\PHPCertificateToolbox\Support
 */
class Utils
{

    /**
     * Return the default value of the given value.
     *
     * @param  mixed  $value
     * @return mixed
     */
    public static function value($value)
    {
        return $value instanceof Closure ? $value() : $value;
    }

}
