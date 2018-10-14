<?php

namespace IanSimpson\OAuth2;

use Monolog\Formatter\LineFormatter;
use Monolog\Handler\SyslogHandler;
use Monolog\Processor\WebProcessor;
use Monolog\Logger;
use SilverStripe\Core\Injector\Factory;

class LogFactory implements Factory
{
    public function create($service, array $params = [])
    {
        $logger = new Logger('ss-oauth2');
        $syslog = new SyslogHandler('SilverStripe_oauth2', LOG_AUTH, Logger::DEBUG);
        $syslog->pushProcessor(new WebProcessor($_SERVER, [
            'url'         => 'REQUEST_URI',
            'http_method' => 'REQUEST_METHOD',
            'server'      => 'SERVER_NAME',
            'referrer'    => 'HTTP_REFERER',
        ]));
        $formatter = new LineFormatter("%level_name%: %message% %context% %extra%");
        $syslog->setFormatter($formatter);
        $logger->pushHandler($syslog);

        return $logger;
    }
}
