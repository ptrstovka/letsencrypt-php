<?php

namespace Elphin\LEClient\Exception;

/**
 * Class LogicException represents an integration problem - the code is being used incorrectly
 */
class LogicException extends \LogicException implements LEClientException
{
}
