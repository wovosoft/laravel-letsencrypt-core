<?php

namespace Wovosoft\LaravelLetsencryptCore\Console\Commands;

use Exception;
use Illuminate\Console\Command;
use Illuminate\Support\Collection;
use Wovosoft\LaravelLetsencryptCore\Client;
use Wovosoft\LaravelLetsencryptCore\Data\Authorization;
use Wovosoft\LaravelLetsencryptCore\Data\Order;
use Wovosoft\LaravelLetsencryptCore\Enums\Modes;
use function Laravel\Prompts\outro;
use function Laravel\Prompts\select;
use function Laravel\Prompts\spin;
use function Laravel\Prompts\table;
use function Laravel\Prompts\text;

class Ssl extends Command
{
    private Client $client;
    /**
     * @var Collection<int,Authorization>
     */
    private Collection $authorizations;
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'letsencrypt:ssl';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Command description';

    private array $domains;
    private Order $order;
    private array $selfTestCases = [];
    private bool $isLocallyVerified = false;

    /**
     * Execute the console command.
     * @throws Exception
     */
    public function handle()
    {
        $this
            ->createClient()
            ->createOrderAndSetAuthorizations()
            ->displayDomainAuthorizationChallenges()
            ->verifyConfigurationAndGenerateCertificates();

    }

    /**
     * Self test
     * @return void
     * @throws Exception
     */
    private function verifyConfigurationAndGenerateCertificates()
    {
        outro("Ownership Verification Configuration");

        $this->info("With DNS validation, after the selfTest has confirmed that DNS has been updated, it is recommended you wait some additional time before proceeding, e.g. sleep(30);. This is because Let’s Encrypt will perform multiple viewpoint validation, and your DNS provider may not have completed propagating the changes across their network.\nIf you proceed too soon, Let's Encrypt will fail to validate.");

        $case = select(
            label: 'Select Test Case',
            options: array_keys($this->selfTestCases),
            required: true
        );

        $result = spin(
            callback: function () use ($case) {
                return $this->client->selfTest(
                    authorization: $this->selfTestCases[$case],
                    type: $case,
                );
            },
            message: 'Verifying Your Configuration',
        );

        if (!$result) {
            $this->error("Could not verify ownership via $case");
        } else {
            $isValidatedOnline = $this->validateOnline($this->selfTestCases[$case], $case);
            if ($isValidatedOnline) {
                dump($this->getCertificates());
            }
        }
    }

    /**
     * @throws Exception
     */
    private function getCertificates()
    {
        $isReady = spin(
            callback: fn() => $this->client->isReady($this->order),
            message: "Checking Order..."
        );

        if (!$isReady) {
            $this->error("Order is not ready");
        }

        return spin(
            callback: function () {
                $certificate = $this->client->getCertificate($this->order);

                return [
                    "certificate.cert" => $certificate->getCertificate(),
                    "private.key" => $certificate->getPrivateKey(),
                    "domain_certificate" => $certificate->getCertificate(false),
                    "intermediate_certificate" => $certificate->getIntermediate(),
                ];
            },
            message: "Generating SSL Certificates..."
        );
    }

    /**
     * @throws Exception
     */
    private function validateOnline(Authorization $authorization, string $type): bool|string
    {
        if ($type == Client::VALIDATION_HTTP) {
            return $this->client->validate($authorization->getHttpChallenge());
        } elseif ($type == Client::VALIDATION_DNS) {
            return $this->client->validate($authorization->getDnsChallenge());
        }
        return false;
    }

    private function displayDomainAuthorizationChallenges(): static
    {
        foreach ($this->authorizations as $authorization) {
            //push test cases
            $this->selfTestCases[Client::VALIDATION_HTTP] = $authorization;
            $this->selfTestCases[Client::VALIDATION_DNS] = $authorization;


            outro("HTTP Authorization for {$authorization->getDomain()}");
            $this->info(
                '1. Create a folder ".well-known" in the root folder'
                . ' of your domain. And inside the ".well-known" create'
                . ' another folder "acme-challenge". Then upload the'
                . ' above file(s) inside the acme-challenge folder.'
            );

            $file = $authorization->getFile();

            $this->info("2. File Should be accessible at \"{$authorization->getDomain()}/.well-known/acme-challenge/{$file->getFilename()}\"");

            table(
                headers: ['File Name', 'File Content'],
                rows: [
                    [
                        $file->getFilename(),
                        $file->getContents()
                    ]
                ]
            );

            $txtRecord = $authorization->getTxtRecord();
            outro("DNS Authorization for {$authorization->getDomain()}");
            $this->showDnsAuthorizationHints();
            table(
                headers: ['Record Name', 'Record Value'],
                rows: [
                    [
                        $txtRecord->getName(),
                        $txtRecord->getValue()
                    ]
                ]
            );
        }

        return $this;
    }

    /**
     * @throws Exception
     */
    private function createOrderAndSetAuthorizations(): static
    {
        $domains = text(
            label: "Domains",
            placeholder: "Write down the domains",
            default: "mahfuj-pos.wovosoft.com",
            required: true,
            hint: "Domains Comma Separated",
        );

        $this->domains = str($domains)->explode(",")->toArray();

        spin(
            callback: function () {
                $this->order = $this->client
                    ->createOrder(
                        domains: $this->domains,
                    );
            },
            message: 'Creating Order...'
        );

        spin(
            callback: function () {
                $this->authorizations = $this->client->authorize($this->order);
            },
            message: 'Fetching Authorizations...'
        );


        return $this;
    }

    /**
     * @throws Exception
     */
    private function createClient(): static
    {
        $username = text(
            label: 'Enter User Name (Email Address)',
            placeholder: 'Email Address',
            default: 'narayanadhikary24@gmail.com',
            required: true,
            hint: "Let's Encrypt Email Address"
        );

        $mode = select(
            label: 'Select Mode',
            options: [
                Modes::Staging->value => Modes::Staging->name,
                Modes::Live->value => Modes::Live->name,
            ],
            default: Modes::Staging->value,
            required: true,
        );


        spin(
            callback: function () use ($username, $mode) {
                $this->client = new Client(
                    mode: Modes::tryFrom($mode),
                    username: $username,
                );
            },
            message: 'Creating/Fetching Client Information...'
        );

        return $this;
    }


    private function showDnsAuthorizationHints(): void
    {
        $lines = [
            '1. Login to your domain host (or wherever service that is "in control" of your domain).',
            '2. Go to the DNS record settings and create a new TXT record.',
            '3. In the Name/Host/Alias field, enter the domain TXT record from below table for example: "_acme-challenge".',
            '4. In the Value/Answer field enter the verfication code from below table.',
            '5. Wait for few minutes for the TXT record to propagate. You can check if it worked by clicking on the "Check DNS" button. If you have multiple entries, make sure all of them are ok.',
        ];

        foreach ($lines as $line) {
            $this->info($line);
        }
    }
}
