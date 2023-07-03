<?php

namespace Wovosoft\LaravelLetsencryptCore\Data;

class VerificationFile extends BaseData
{
    public function __construct(protected string $filename, protected string $contents)
    {

    }

    /**
     * Return the filename for HTTP validation
     * @return string
     */
    public function getFilename(): string
    {
        return $this->filename;
    }

    /**
     * Return the file contents for HTTP validation
     * @return string
     */
    public function getContents(): string
    {
        return $this->contents;
    }

    public function toArray(): array
    {
        return [
            "filename" => $this->filename,
            "contents" => $this->contents,
        ];
    }
}
