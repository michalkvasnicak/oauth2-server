<?php

namespace OAuth2\Storage;

/**
 * @author Michal Kvasničák <michal.kvasnicak@mink.sk>
 */
interface IScope 
{

    /**
     * Gets scope identifier (used as identification in requests)
     *
     * @return string
     */
    public function getId();

}
