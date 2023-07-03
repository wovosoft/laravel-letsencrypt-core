<?php

namespace Wovosoft\LaravelLetsencryptCore\Data;

use DateTime;

class Account extends BaseData
{
    public function __construct(
        protected array    $contact,
        protected DateTime $createdAt,
        protected bool     $isValid,
        protected string   $initialIp,
        protected string   $accountURL
    )
    {

    }

    /**
     * Return the account ID
     * @return string
     */
    public function getId(): string
    {
        return substr($this->accountURL, strrpos($this->accountURL, '/') + 1);
    }

    /**
     * Return create date for the account
     * @return DateTime
     */
    public function getCreatedAt(): DateTime
    {
        return $this->createdAt;
    }

    /**
     * Return the URL for the account
     * @return string
     */
    public function getAccountURL(): string
    {
        return $this->accountURL;
    }

    /**
     * Return contact data
     * @return array
     */
    public function getContact(): array
    {
        return $this->contact;
    }

    /**
     * Return initial IP
     * @return string
     */
    public function getInitialIp(): string
    {
        return $this->initialIp;
    }

    /**
     * Returns validation status
     * @return bool
     */
    public function isValid(): bool
    {
        return $this->isValid;
    }

    public function toArray(): array
    {
        return [
            "contact" => $this->getContact(),
            "createdAt" => $this->getCreatedAt(),
            "isValid" => $this->isValid(),
            "initialIp" => $this->getInitialIp(),
            "accountURL" => $this->getAccountURL(),
        ];
    }
}
