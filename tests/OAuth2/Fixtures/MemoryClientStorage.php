<?php

namespace tests\OAuth2\Fixtures;

use OAuth2\Storage\IClient;
use OAuth2\Storage\IClientStorage;

/**
 * @author Michal Kvasničák <michal.kvasnicak@mink.sk>
 */
class MemoryClientStorage implements IClientStorage
{

    /**
     * @var IClient[]
     */
    protected $clients = [];


    public function add(IClient $client)
    {
        $this->clients[$client->getId()] = $client;
    }

    /**
     * Gets client by id
     *
     * @param string $id
     *
     * @return IClient|null
     */
    public function get($id)
    {
        return isset($this->clients[$id]) ? $this->clients[$id] : null;
    }
}
 