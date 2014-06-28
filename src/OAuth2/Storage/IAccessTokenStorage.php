<?php

namespace OAuth2\Storage;

/**
 * @author Michal Kvasničák <michal.kvasnicak@mink.sk>
 */
interface IAccessTokenStorage extends ITokenGenerator
{

    /**
     * Gets access token by id
     *
     * @param string $id
     *
     * @return IAccessToken|null
     */
    public function get($id);

}
