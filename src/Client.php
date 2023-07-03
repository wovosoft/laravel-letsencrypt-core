<?php

namespace Wovosoft\LaravelLetsencryptCore;

use Exception;
use GuzzleHttp\Exception\GuzzleException;
use GuzzleHttp\Promise\PromiseInterface;
use Illuminate\Contracts\Filesystem\Filesystem;
use Illuminate\Http\Client\PendingRequest;
use Illuminate\Http\Client\Response;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Storage;
use OpenSSLAsymmetricKey;
use Wovosoft\LaravelLetsencryptCore\Data\Account;
use Wovosoft\LaravelLetsencryptCore\Data\Authorization;
use Wovosoft\LaravelLetsencryptCore\Data\Certificate;
use Wovosoft\LaravelLetsencryptCore\Data\Challenge;
use Wovosoft\LaravelLetsencryptCore\Data\Directories;
use Wovosoft\LaravelLetsencryptCore\Data\Order;
use GuzzleHttp\Client as HttpClient;
use GuzzleHttp\Exception\RequestException;
use Wovosoft\LaravelLetsencryptCore\Enums\Modes;

class Client
{
    const CONTENT_TYPE = 'application/jose+json';
    /**
     * Live url
     */
    const DIRECTORY_LIVE = 'https://acme-v02.api.letsencrypt.org/directory';

    /**
     * Staging url
     */
    const DIRECTORY_STAGING = 'https://acme-staging-v02.api.letsencrypt.org/directory';

    /**
     * Http validation
     */
    const VALIDATION_HTTP = 'http-01';

    /**
     * DNS validation
     */
    const VALIDATION_DNS = 'dns-01';
    protected int $keyLength = 4096;

    protected ?string $nonce = null;

    protected ?Account $account = null;

    protected array $privateKeyDetails;

    protected ?OpenSSLAsymmetricKey $accountKey = null;


    protected ?Directories $directories;


    protected ?string $digest = null;

    protected ?HttpClient $httpClient = null;
    protected ?Filesystem $filesystem;


    /**
     * @throws Exception
     */
    public function __construct(
        public Modes   $mode,
        public string  $username,
        public ?string $basePath = null,
        public ?string $disk = null,
        public ?string $source_ip = null
    )
    {
        if (!$this->basePath) {
            $this->basePath = config("laravel-letsencrypt-core.basepath");
        }
        if ($this->disk) {
            $this->disk = config("laravel-letsencrypt-core.disk");
        }
        $this->init();
    }

    /**
     * @throws Exception
     */
    protected function init(): void
    {
        $this->filesystem = Storage::disk($this->disk);

        $this->directories = new Directories($this->getClient()->get("/directory")->object());

        //Prepare LE account
        $this->loadKeys();

        $this->tosAgree();
        $this->account = $this->getAccount();
    }

    private function getClient(): PendingRequest
    {
        return Http::setClient(client: $this->getHttpClient())->contentType(self::CONTENT_TYPE);
    }

    protected function request($url, array $payload = [], string $method = 'POST'): PromiseInterface|Response
    {
        $response = $this->getClient()->$method($url, $payload);
        $this->nonce = $response->header('Replay-Nonce');

        return $response;
    }

    protected function loadKeys(): void
    {
        //Make sure a private key is in place
        if (!$this->filesystem->exists($this->getPath('account.pem'))) {
            $this->filesystem->put(
                $this->getPath('account.pem'),
                Helper::getNewKey($this->keyLength)
            );
        }
        $privateKey = $this->filesystem->get($this->getPath('account.pem'));
        $privateKey = openssl_pkey_get_private($privateKey);
        $this->privateKeyDetails = openssl_pkey_get_details($privateKey);
    }

    /**
     * Agree to the terms of service
     *
     * @throws Exception
     */
    protected function tosAgree(): void
    {
        $this->request(
            $this->directories->newAccount,
            $this->signPayloadJWK(
                [
                    'contact'              => [
                        'mailto:' . $this->username,
                    ],
                    'termsOfServiceAgreed' => true,
                ],
                $this->directories->newAccount
            )
        );
    }

    /**
     * Get an existing order by ID
     *
     * @param $id
     * @return Order
     * @throws Exception
     */
    public function getOrder($id): Order
    {

        $url = str($this->directories->newOrder)
            ->replace('new-order', 'order')
            ->append('/' . $this->getAccount()->getId() . '/' . $id)
            ->value();

        $data = $this->request($url, $this->signPayloadKid(null, $url))->json();

        return new Order(
            domains: collect($data['identifiers'])->map(fn($identifier) => $identifier['value'])->toArray(),
            url: $url,
            status: $data['status'],
            expiresAt: $data['expires'],
            identifiers: $data['identifiers'],
            authorizations: $data['authorizations'],
            finalizeURL: $data['finalize']
        );
    }

    /**
     * Get ready status for order
     *
     * @param Order $order
     * @return bool
     * @throws Exception
     */
    public function isReady(Order $order): bool
    {
        $order = $this->getOrder($order->getId());
        return $order->getStatus() == 'ready';
    }


    /**
     * Create a new order
     *
     * @param array $domains
     * @return Order
     * @throws Exception
     */
    public function createOrder(array $domains): Order
    {
        $response = $this
            ->request($this->directories->newOrder, $this->signPayloadKid(
                [
                    'identifiers' => collect($domains)->map(fn($domain) => [
                        "type"  => "dns",
                        "value" => $domain
                    ])->toArray(),
                ],
                $this->directories->newOrder
            ));

        $data = $response->json();

        return new Order(
            domains: $domains,
            url: $response->header('Location'),
            status: $data['status'],
            expiresAt: $data['expires'],
            identifiers: $data['identifiers'],
            authorizations: $data['authorizations'],
            finalizeURL: $data['finalize']
        );
    }

    /**
     * Obtain authorizations
     *
     * @param Order $order
     * @return Collection<Authorization>
     */
    public function authorize(Order $order): Collection
    {
        return $order
            ->getAuthorizationURLs()
            ->map(function (string $authorizationURL) {
                $response = $this->request(
                    $authorizationURL,
                    $this->signPayloadKid(null, $authorizationURL)
                );

                $data = $response->json();

                $authorization = new Authorization(
                    domain: $data['identifier']['value'],
                    expires: $data['expires'],
                    digest: $this->getDigest()
                );

                foreach ($data['challenges'] as $challengeData) {
                    $authorization->addChallenge(
                        challenge: new Challenge(
                            authorizationURL: $authorizationURL,
                            type: $challengeData['type'],
                            status: $challengeData['status'],
                            url: $challengeData['url'],
                            token: $challengeData['token']
                        )
                    );
                }

                return $authorization->toArray();
            });
    }

    /**
     * Run a self-test for the authorization
     * @param Authorization $authorization
     * @param string        $type
     * @param int           $maxAttempts
     * @return bool
     * @throws GuzzleException
     */
    public function selfTest(Authorization $authorization, string $type = self::VALIDATION_HTTP, int $maxAttempts = 15): bool
    {
        if ($type == self::VALIDATION_HTTP) {
            return $this->selfHttpTest($authorization, $maxAttempts);
        } elseif ($type == self::VALIDATION_DNS) {
            return $this->selfDNSTest($authorization, $maxAttempts);
        }
        return false;
    }

    /**
     * Validate a challenge
     *
     * @param Challenge $challenge
     * @param int       $maxAttempts
     * @return bool
     * @throws Exception
     */
    public function validate(Challenge $challenge, int $maxAttempts = 15): bool
    {
        $this->request(
            $challenge->getUrl(),
            $this->signPayloadKid([
                'keyAuthorization' => $challenge->getToken() . '.' . $this->getDigest(),
            ], $challenge->getUrl())
        );

        do {
            $response = $this->request(
                $challenge->getAuthorizationURL(),
                $this->signPayloadKid(null, $challenge->getAuthorizationURL())
            );

            $data = $response->json();

            if ($maxAttempts > 1 && $data['status'] != 'valid') {
                sleep(ceil(15 / $maxAttempts));
            }
            $maxAttempts--;
        } while ($maxAttempts > 0 && $data['status'] != 'valid');

        return (isset($data['status']) && $data['status'] == 'valid');
    }

    /**
     * Return a certificate
     *
     * @param Order $order
     * @return Certificate
     * @throws Exception
     */
    public function getCertificate(Order $order): Certificate
    {
        $privateKey = Helper::getNewKey($this->keyLength);
        $csr = Helper::getCsr($order->getDomains(), $privateKey);
        $der = Helper::toDer($csr);

        $response = $this->request(
            $order->getFinalizeURL(),
            $this->signPayloadKid(
                ['csr' => Helper::toSafeString($der)],
                $order->getFinalizeURL()
            )
        );

        $data = $response->object();
        $certificateResponse = $this->request(
            $data['certificate'],
            $this->signPayloadKid(null, $data['certificate'])
        );
        $chain = preg_replace('/^[ \t]*[\r\n]+/m', '', (string)$certificateResponse->body());
        return new Certificate($privateKey, $csr, $chain);
    }

    /**
     * Return LE account information
     *
     * @return Account
     * @throws Exception
     */
    public function getAccount(): Account
    {
        if ($this->account) {
            return $this->account;
        }
        $response = $this
            ->getClient()
            ->contentType('application/jose+json')
            ->post($this->directories->newAccount, $this->signPayloadJWK(
                ['onlyReturnExisting' => true],
                $this->directories->newAccount
            ));

        $this->nonce = $response->header('Replay-Nonce');
        $data = $response->json();

        return new Account(
            contact: $data['contact'],
            createdAt: (new \DateTime())->setTimestamp(strtotime($data['createdAt'])),
            isValid: ($data['status'] === 'valid'),
            initialIp: $data['initialIp'],
            accountURL: $response->header('Location')
        );
    }

    /**
     * Returns the ACME api configured Guzzle Client
     * @return HttpClient
     */
    protected function getHttpClient(): HttpClient
    {
        if ($this->httpClient === null) {
            $config = [
                'base_uri' => match ($this->mode) {
                    Modes::Staging => self::DIRECTORY_STAGING,
                    Modes::Live => self::DIRECTORY_LIVE
                },
            ];
            if ($this->source_ip) {
                $config['curl.options']['CURLOPT_INTERFACE'] = $this->source_ip;
            }
            $this->httpClient = new HttpClient($config);
        }
        return $this->httpClient;
    }

    /**
     * Returns a Guzzle Client configured for self test
     * @return HttpClient
     */
    protected function getSelfTestClient(): HttpClient
    {
        return new HttpClient([
            'verify'          => false,
            'timeout'         => 10,
            'connect_timeout' => 3,
            'allow_redirects' => true,
        ]);
    }

    /**
     * Self HTTP test
     * @param Authorization $authorization
     * @param               $maxAttempts
     * @return bool
     * @throws GuzzleException
     */
    protected function selfHttpTest(Authorization $authorization, $maxAttempts): bool
    {
        do {
            $maxAttempts--;
            try {
                $response = $this->getSelfTestClient()->request(
                    'GET',
                    'http://' . $authorization->getDomain() . '/.well-known/acme-challenge/' .
                    $authorization->getFile()->getFilename()
                );
                $contents = (string)$response->getBody();
                if ($contents == $authorization->getFile()->getContents()) {
                    return true;
                }
            } catch (RequestException $e) {
            }
        } while ($maxAttempts > 0);

        return false;
    }

    /**
     * Self DNS test client that uses Cloudflare's DNS API
     * @param Authorization $authorization
     * @param               $maxAttempts
     * @return bool
     * @throws GuzzleException
     */
    protected function selfDNSTest(Authorization $authorization, $maxAttempts): bool
    {
        do {
            $response = $this->getSelfTestDNSClient()->get(
                '/dns-query',
                [
                    'query' => [
                        'name' => $authorization->getTxtRecord()->getName(),
                        'type' => 'TXT',
                    ],
                ]
            );
            $data = json_decode((string)$response->getBody(), true);
            if (isset($data['Answer'])) {
                foreach ($data['Answer'] as $result) {
                    if (trim($result['data'], "\"") == $authorization->getTxtRecord()->getValue()) {
                        return true;
                    }
                }
            }
            if ($maxAttempts > 1) {
                sleep(ceil(45 / $maxAttempts));
            }
            $maxAttempts--;
        } while ($maxAttempts > 0);

        return false;
    }

    /**
     * Return the preconfigured client to call Cloudflare's DNS API
     * @return HttpClient
     */
    protected function getSelfTestDNSClient(): HttpClient
    {
        return new HttpClient([
            'base_uri'        => 'https://cloudflare-dns.com',
            'connect_timeout' => 10,
            'headers'         => [
                'Accept' => 'application/dns-json',
            ],
        ]);
    }


    /**
     * Get a formatted path
     *
     * @param null $path
     * @return string
     */
    protected function getPath($path = null): string
    {
        $userDirectory = preg_replace('/[^a-z0-9]+/', '-', strtolower($this->username));

        return $this->basePath . DIRECTORY_SEPARATOR . $userDirectory . ($path === null ? '' : DIRECTORY_SEPARATOR . $path);
    }

    /**
     * Return the Flysystem filesystem
     * @return Filesystem
     */
    public function getFilesystem(): Filesystem
    {
        return $this->filesystem;
    }

    /**
     * Get key fingerprint
     *
     * @return string
     * @throws Exception
     */
    public function getDigest(): string
    {
        if ($this->digest === null) {
            $this->digest = Helper::toSafeString(hash('sha256', json_encode($this->getJWKHeader()), true));
        }

        return $this->digest;
    }


    /**
     * @throws Exception
     */
    protected function getAccountKey(): bool|OpenSSLAsymmetricKey
    {
        if ($this->accountKey === null) {
            $this->accountKey = openssl_pkey_get_private($this->getFilesystem()->get($this->getPath('account.pem')));
        }

        if ($this->accountKey === false) {
            throw new Exception('Invalid account key');
        }

        return $this->accountKey;
    }

    /**
     * Get the header
     *
     * @return array
     * @throws Exception
     */
    protected function getJWKHeader(): array
    {
        return [
            'e'   => Helper::toSafeString(Helper::getKeyDetails($this->getAccountKey())['rsa']['e']),
            'kty' => 'RSA',
            'n'   => Helper::toSafeString(Helper::getKeyDetails($this->getAccountKey())['rsa']['n']),
        ];
    }

    /**
     * Get JWK envelope
     *
     * @param $url
     * @return array
     * @throws Exception
     */
    protected function getJWK($url): array
    {
        //Require a nonce to be available
        if ($this->nonce === null) {
            $response = $this->getClient()->head($this->directories->newNonce);
            $this->nonce = $response->header('Replay-Nonce');
        }
        return [
            'alg'   => 'RS256',
            'jwk'   => $this->getJWKHeader(),
            'nonce' => $this->nonce,
            'url'   => $url,
        ];
    }

    /**
     * Get KID envelope
     *
     * @param $url
     * @return array
     */
    protected function getKID($url): array
    {
        $response = $this
            ->getClient()
            ->head($this->directories->newNonce);

        return [
            "alg"   => "RS256",
            "kid"   => $this->account->getAccountURL(),
            "nonce" => $response->header('Replay-Nonce'),
            "url"   => $url,
        ];
    }

    /**
     * Transform the payload to the JWS format
     *
     * @param $payload
     * @param $url
     * @return array
     * @throws Exception
     */
    protected function signPayloadJWK($payload, $url): array
    {
        $payload = is_array($payload) ? str_replace('\\/', '/', json_encode($payload)) : '';
        $payload = Helper::toSafeString($payload);
        $protected = Helper::toSafeString(json_encode($this->getJWK($url)));

        $result = openssl_sign($protected . '.' . $payload, $signature, $this->getAccountKey(), "SHA256");

        if ($result === false) {
            throw new Exception('Could not sign');
        }

        return [
            'protected' => $protected,
            'payload'   => $payload,
            'signature' => Helper::toSafeString($signature),
        ];
    }

    /**
     * Transform the payload to the KID format
     *
     * @param $payload
     * @param $url
     * @return array
     * @throws Exception
     */
    protected function signPayloadKid($payload, $url): array
    {
        $payload = is_array($payload) ? str_replace('\\/', '/', json_encode($payload)) : '';

        $payload = Helper::toSafeString($payload);
        $protected = Helper::toSafeString(json_encode($this->getKID($url)));

        $result = openssl_sign($protected . '.' . $payload, $signature, $this->getAccountKey(), "SHA256");
        if ($result === false) {
            throw new Exception('Could not sign');
        }

        return [
            'protected' => $protected,
            'payload'   => $payload,
            'signature' => Helper::toSafeString($signature),
        ];
    }

    public function getDirectories(): ?Directories
    {
        return $this->directories;
    }
}
