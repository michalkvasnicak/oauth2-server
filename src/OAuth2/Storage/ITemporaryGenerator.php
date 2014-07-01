<?php

namespace OAuth2\Storage;

/**
 * @author Michal Kvasničák <michal.kvasnicak@mink.sk>
 * @copyright Mink Ltd, 2014
 */
interface ITemporaryGenerator 
{

    /**
     * Sets lifetime for generator
     *
     * @param int $lifetime
     */
    public function setLifetime($lifetime);

}
 