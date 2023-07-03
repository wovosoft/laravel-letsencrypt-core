<?php

namespace Wovosoft\LaravelLetsencryptCore\Data;

class Challenge extends BaseData
{
    public function __construct(
        protected string $authorizationURL,
        protected string $type,
        protected string $status,
        protected string $url,
        protected string $token
    )
    {

    }

    public function getUrl(): string
    {
        return $this->url;
    }

    public function getType(): string
    {
        return $this->type;
    }

    public function getToken(): string
    {
        return $this->token;
    }

    public function getStatus(): string
    {
        return $this->status;
    }

    public function getAuthorizationURL(): string
    {
        return $this->authorizationURL;
    }

    public function toArray(): array
    {
        return [
            "authorizationURL" => $this->authorizationURL,
            "type"             => $this->type,
            "status"           => $this->status,
            "url"              => $this->url,
            "token"            => $this->token,
        ];
    }
}
