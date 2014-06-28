<?php

namespace tests\OAuth2\Fixtures;


/**
 * @author Michal Kvasničák <michal.kvasnicak@mink.sk>
 */
abstract class ABaseTokenStorage
{

    /** @var  ABaseToken[] */
    protected $tokens;


    public function add(ABaseToken $token)
    {
        $this->tokens[$token->getId()] = $token;
    }


    public function get($id)
    {
        return isset($this->tokens[$id]) ?  $this->tokens[$id] : null;
    }

}
 