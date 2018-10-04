<?php

namespace IanSimpson\Psr7;

use GuzzleHttp\Psr7\Response;

/**
 * @package psr7-adapters
 */
class HttpResponseAdapter extends AbstractHttpAdapter
{
    /**
     * {@inheritDoc}
     */
    public function toPsr7($input)
    {
        return new Response(
            $input->getStatusCode(),
            $input->getHeaders(),
            $input->getBody(),
            $this->getProtocolVersion(),
            $input->getStatusDescription()
        );
    }

    /**
     * {@inheritDoc}
     */
    public function fromPsr7($input)
    {
        $adapted = new \SS_HTTPResponse(
            (string) $input->getBody(),
            $input->getStatusCode(),
            $input->getReasonPhrase()
        );

        $this->importHeaders($input, $adapted);

        return $adapted;
    }
}
