<?php

namespace OAuth2\Storage;

/**
 * @author Michal Kvasničák <michal.kvasnicak@mink.sk>
 */
interface IUser 
{


    /**
     * Gets user assigned scopes
     *
     * @return IScope[]
     */
    public function getScopes();

}
