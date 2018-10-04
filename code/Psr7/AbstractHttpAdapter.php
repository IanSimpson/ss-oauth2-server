<?php

namespace IanSimpson\Psr7;

use Psr\Http\Message\MessageInterface;
use SS_HTTPRequest;
use SS_HTTPResponse;

/**
 * Provides common functionality used between Request and Response objects
 *
 * @package psr7-adapters
 */
abstract class AbstractHttpAdapter
{
    /**
     * @var string
     */
    protected $protocolVersion;

    /**
     * Perform a conversion from a HTTPResponse or HTTPRequest into the corresponding PSR-7 interface
     *
     * @param  SS_HTTPRequest|SS_HTTPResponse $input
     * @return MessageInterface
     */
    abstract public function toPsr7($input);

    /**
     * Perform a conversion from a PSR-7 interface to the corresponding HTTPRequest or HTTPResponse class
     *
     * @param  MessageInterface $input
     * @return SS_HTTPRequest|SS_HTTPResponse
     */
    abstract public function fromPsr7($input);

    /**
     * PSR-7 interfaces support multiple headers per type, whereas SilverStripe classes do not.
     *
     * This method will assign headers as a comma delimited string from the PSR-7 interface to the SilverStripe class
     *
     * @param MessageInterface         $from
     * @param SS_HTTPRequest|SS_HTTPResponse $to
     */
    public function importHeaders(MessageInterface $from, $to)
    {
        foreach ($from->getHeaders() as $key => $headers) {
            foreach ($headers as $header) {
                $to->addHeader($key, $from->getHeaderLine($key));
            }
        }
    }

    /**
     * Get the protocol version - either from a previously set value, or from the server
     *
     * @return string E.g. "1.1"
     */
    public function getProtocolVersion()
    {
        if ($this->protocolVersion) {
            return $this->protocolVersion;
        }

        $protocolAndVersion = $_SERVER['SERVER_PROTOCOL'];
        list($protocol, $version) = explode('/', $protocolAndVersion);
        return $version;
    }

    /**
     * Set the protocol version
     *
     * @param  string $version
     * @return $this
     */
    public function setProtocolVersion($version = '1.1')
    {
        $this->protocolVersion = $version;
        return $this;
    }
}
