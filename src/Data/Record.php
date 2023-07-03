<?php

namespace Wovosoft\LaravelLetsencryptCore\Data;

class Record extends BaseData
{

    public function __construct(protected string $name, protected string $value)
    {

    }

    /**
     * Return the DNS TXT record name for validation
     * @return string
     */
    public function getName(): string
    {
        return $this->name;
    }

    /**
     * Return the record value for DNS validation
     * @return string
     */
    public function getValue(): string
    {
        return $this->value;
    }

    public function toArray(): array
    {
        return [
            "name"  => $this->name,
            "value" => $this->value,
        ];
    }
}
