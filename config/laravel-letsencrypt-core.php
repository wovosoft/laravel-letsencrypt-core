<?php

use Wovosoft\LaravelLetsencryptCore\Enums\Modes;

return [
    "mode"                                => Modes::Staging,
    "basepath"                            => "le",
    "disk"                                => "local",
    "verification_file_storage_directory" => "/home/wovosoft/Downloads/letsencrypt",
];
