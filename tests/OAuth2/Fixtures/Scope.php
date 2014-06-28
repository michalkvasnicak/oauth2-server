<?php

namespace tests\OAuth2\Fixtures;

use OAuth2\Storage\IScope;

/**
 * @author Michal Kvasničák <michal.kvasnicak@mink.sk>
 */
class Scope implements IScope
{

    /**
     * @var mixed
     */
    private $id;


    public function __construct($id)
    {
        $this->id = $id;
    }

    /**
     * Gets scope identifier (used as identification in requests)
     *
     * @return string
     */
    public function getId()
    {
        return $this->id;
    }
}
 