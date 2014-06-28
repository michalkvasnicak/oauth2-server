<?php

namespace OAuth2\Storage;

/**
 * @author Michal Kvasničák <michal.kvasnicak@mink.sk>
 */
interface IClientStorage 
{

    /**
     * Gets client by id
     *
     * @param string $id
     *
     * @return IClient|null
     */
    public function get($id);

}
