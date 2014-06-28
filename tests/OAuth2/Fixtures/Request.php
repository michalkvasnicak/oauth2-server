<?php

namespace tests\OAuth2\Fixtures;

use OAuth2\Http\IRequest;

/**
 * @author Michal Kvasničák <michal.kvasnicak@mink.sk>
 */
class Request implements IRequest
{

    /**
     * @var
     */
    private $method;

    /**
     * @var array
     */
    private $headers;

    /**
     * @var array
     */
    private $request;

    /**
     * @var array
     */
    private $query;

    public function __construct($method, array $headers = [], array $request = [], array $query = [])
    {
        $this->method = $method;
        $this->headers = $headers;
        $this->request = $request;
        $this->query = $query;
    }



    /**
     * Gets all headers or header by name
     *
     * If name is given but does not exist in headers, default value is returned
     *
     * @param null|string $name
     * @param null|mixed $default
     *
     * @return array|mixed
     */
    public function headers($name = null, $default = null)
    {
        return isset($this->headers[$name]) ? $this->headers[$name] : $default;
    }

    /**
     * Gets all query parameters or parameter by name
     *
     * If name is given but does not exist in query (GET) parameters, default value is returned
     *
     * @param null|string $name
     * @param null|mixed $default
     *
     * @return array|mixed
     */
    public function query($name = null, $default = null)
    {
        return isset($this->query[$name]) ? $this->query[$name] : $default;
    }

    /**
     * Gets all POST parameters or parameter specified by name
     *
     * If name is given but does not exist in POST parameters, default value is returned
     *
     * @param null|string $name
     * @param null|mixed $default
     *
     * @return array|mixed
     */
    public function request($name = null, $default = null)
    {
        return isset($this->request[$name]) ? $this->request[$name] : $default;
    }

    /**
     * Is request sent using given HTTP method?
     *
     * @param string $name
     *
     * @return bool
     */
    public function isMethod($name)
    {
        return strcasecmp($name, $this->method) === 0;
    }
}
 