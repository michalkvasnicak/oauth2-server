<?php

namespace OAuth2\Http;

/**
 * @author Michal Kvasničák <michal.kvasnicak@mink.sk>
 */
interface IRequest
{


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
    public function headers($name = null, $default = null);


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
    public function query($name = null, $default = null);


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
    public function request($name = null, $default = null);


    /**
     * Is request sent using given HTTP method?
     *
     * @param string $name
     *
     * @return bool
     */
    public function isMethod($name);


}
