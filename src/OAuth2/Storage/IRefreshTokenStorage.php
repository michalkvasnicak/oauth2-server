<?php

namespace OAuth2\Storage;

/**
 * @author Michal Kvasničák <michal.kvasnicak@mink.sk>
 */
interface IRefreshTokenStorage extends ITokenGenerator
{


    /**
     * Gets refresh token by its identifier
     *
     * @param string $id
     *
     * @return IRefreshToken|null
     */
    public function get($id);

}
