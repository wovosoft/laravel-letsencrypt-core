<?php

namespace Wovosoft\LaravelLetsencryptCore\Data;

use Illuminate\Support\Carbon;
use Wovosoft\LaravelLetsencryptCore\Client;
use Wovosoft\LaravelLetsencryptCore\Helper;

class Authorization extends BaseData
{
    protected array $challenges = [];
    protected Carbon $expires;

    public function __construct(
        protected readonly string $domain,
        string|\DateTime          $expires,
        protected readonly string $digest
    )
    {
        if (is_string($expires)) {
            $this->expires = Carbon::parse(strtotime($expires));
        }
    }

    /**
     * Add a challenge to the authorization
     * @param Challenge $challenge
     */
    public function addChallenge(Challenge $challenge): void
    {
        $this->challenges[] = $challenge;
    }

    /**
     * Return the domain that is being authorized
     * @return string
     */
    public function getDomain(): string
    {
        return $this->domain;
    }


    /**
     * Return the expiry of the authorization
     * @return Carbon
     */
    public function getExpires(): Carbon
    {
        return $this->expires;
    }

    /**
     * Return array of challenges
     * @return Challenge[]
     */
    public function getChallenges(): array
    {
        return $this->challenges;
    }

    /**
     * Return the HTTP challenge
     * @return Challenge|bool
     */
    public function getHttpChallenge(): Challenge|bool
    {
        foreach ($this->getChallenges() as $challenge) {
            if ($challenge->getType() == Client::VALIDATION_HTTP) {
                return $challenge;
            }
        }

        return false;
    }

    /**
     * @return Challenge|bool
     */
    public function getDnsChallenge(): Challenge|bool
    {
        foreach ($this->getChallenges() as $challenge) {
            if ($challenge->getType() == Client::VALIDATION_DNS) {
                return $challenge;
            }
        }

        return false;
    }

    /**
     * Return File object for the given challenge
     * @return VerificationFile|bool
     */
    public function getFile(): VerificationFile|bool
    {
        $challenge = $this->getHttpChallenge();
        if ($challenge !== false) {
            return new VerificationFile($challenge->getToken(), $challenge->getToken() . '.' . $this->digest);
        }
        return false;
    }

    /**
     * Returns the DNS record object
     *
     * @return Record|bool
     */
    public function getTxtRecord(): Record|bool
    {
        $challenge = $this->getDnsChallenge();

        if ($challenge !== false) {
            $hash = hash('sha256', $challenge->getToken() . '.' . $this->digest, true);
            $value = Helper::toSafeString($hash);
            return new Record('_acme-challenge.' . $this->getDomain(), $value);
        }

        return false;
    }

    public function toArray(): array
    {
        return [
            "domain" => $this->domain,
            "expires" => $this->expires,
            "challenges" => collect($this->challenges)->map(fn(Challenge $challenge) => $challenge->toArray())->toArray(),
//            "http_challenge" => $this->getHttpChallenge()?->toArray(),
//            "dns_challenge" => $this->getDnsChallenge()?->toArray(),
            "file" => $this->getFile()?->toArray(),
            "txt_record" => $this->getTxtRecord()?->toArray(),
        ];
    }
}
