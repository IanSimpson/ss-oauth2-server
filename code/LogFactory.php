<?php

namespace IanSimpson;

use Monolog\Formatter\LineFormatter;
use Monolog\Handler\StreamHandler;
use Monolog\Logger;
use SilverStripe\Framework\Injector\Factory;

class LogFactory implements Factory
{
    public function create($service, array $params = [])
    {
        $logger = new Logger('ss-oauth2');
        $outputHandler = new StreamHandler(STDOUT);
        $outputHandler->setFormatter(new LineFormatter("%level_name% - %message%\n"));
        $logger->pushHandler($outputHandler);

        return $logger;
    }
}
