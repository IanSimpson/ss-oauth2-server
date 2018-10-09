<?php

namespace IanSimpson\Psr7;

use GuzzleHttp\Psr7\ServerRequest;
use SS_HTTPRequest;

/**
 * @package psr7-adapters
 */
class HttpRequestAdapter extends AbstractHttpAdapter
{
    /**
     * @var array
     */
    protected $serverVars;

    /**
     * Set up the server vars - they can be overridden if required
     */
    public function __construct()
    {
        $this->setServerVars($_SERVER);
    }

    /**
     * {@inheritDoc}
     */
    public function toPsr7($input)
    {
        $request = new ServerRequest(
            $input->httpMethod(),
            $this->getUri($input->getURL()),
            $input->getHeaders(),
            $input->getBody(),
            $this->getProtocolVersion(),
            $this->getServerVars()
        );

        if (!empty($input->getVars())) {
            $request = $request->withQueryParams($input->getVars());
        }

        if (!empty($input->postVars())) {
            $request = $request->withParsedBody($input->postVars());
        }

        return $request;
    }

    /**
     * {@inheritDoc}
     */
    public function fromPsr7($input)
    {
        $adapted = new SS_HTTPRequest(
            $input->getMethod(),
            (string) $input->getUri()->getPath(),
            $input->getQueryParams(),
            $input->getParsedBody(),
            (string) $input->getBody()
        );

        $this->importHeaders($input, $adapted);

        return $adapted;
    }

    /**
     * Get the full request URI (can be empty, but probably won't be)
     *
     * @param  string $path
     * @return string
     */
    public function getUri($path)
    {
        $vars = $this->getServerVars();

        $uri = '';
        $protocol = (isset($vars['HTTPS']) || $vars['SERVER_PORT'] === '443') ? 'https' : 'http';
        $uri .= $protocol . '://';

        if (!empty($vars['PHP_AUTH_USER'])) {
            $uri .= $vars['PHP_AUTH_USER'];

            if (!empty($vars['PHP_AUTH_PW'])) {
                $uri .= ':' . $vars['PHP_AUTH_PW'];
            }

            $uri .= '@';
        }

        if (!empty($vars['HTTP_HOST'])) {
            $uri .= $vars['HTTP_HOST'];
        }

        $uri .= '/' . ltrim($path, '/');

        return $uri;
    }

    /**
     * @return array
     */
    public function getServerVars()
    {
        return $this->serverVars;
    }

    /**
     * @param  array $vars
     * @return $this
     */
    public function setServerVars(array $vars)
    {
        $this->serverVars = $vars;
        return $this;
    }
}
