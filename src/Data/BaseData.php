<?php

namespace Wovosoft\LaravelLetsencryptCore\Data;

use Illuminate\Support\Collection;

class BaseData
{
    public function toCollection(): Collection
    {
        return collect($this->toArray());
    }
}
