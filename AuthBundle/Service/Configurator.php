<?php

namespace AuthBundle\Service;

class Configurator
{
    public function setConfig($configs)
    {
        foreach ($configs as $key => $value) {
            $this->$key = $value;
        }
    }

    public function get($attribute)
    {
        return $this->$attribute;
    }
}
