<?php

namespace Wovosoft\LaravelLetsencryptCore\Data;

use Wovosoft\LaravelLetsencryptCore\Helper;

class Certificate extends BaseData
{
    protected string $certificate;

    protected string $intermediateCertificate;

    protected \DateTime $expiryDate;

    /**
     * @throws \Exception
     */
    public function __construct(
        protected string $privateKey,
        protected string $csr,
        protected string $chain
    )
    {
        [
            $this->certificate,
            $this->intermediateCertificate,
        ] = Helper::splitCertificate($chain);

        $this->expiryDate = Helper::getCertExpiryDate($chain);
    }

    /**
     * Get the certificate signing request
     * @return string
     */
    public function getCsr(): string
    {
        return $this->csr;
    }

    /**
     * Get the expiry date of the current certificate
     * @return \DateTime
     */
    public function getExpiryDate(): \DateTime
    {
        return $this->expiryDate;
    }

    /**
     * Return the certificate as a multi line string, by default it includes the intermediate certificate as well
     *
     * @param bool $asChain
     * @return string
     */
    public function getCertificate(bool $asChain = true): string
    {
        return $asChain ? $this->chain : $this->certificate;
    }

    /**
     * Return the intermediate certificate as a multi line string
     * @return string
     */
    public function getIntermediate(): string
    {
        return $this->intermediateCertificate;
    }

    /**
     * Return the private key as a multi line string
     * @return string
     */
    public function getPrivateKey(): string
    {
        return $this->privateKey;
    }

    public function toArray(): array
    {
        return [
            "csr"                      => $this->csr,
            "expiry_date"              => $this->expiryDate,
            "certificate"              => $this->certificate,
            "intermediate_certificate" => $this->intermediateCertificate,
            "private_key"              => $this->privateKey,
        ];
    }
}
