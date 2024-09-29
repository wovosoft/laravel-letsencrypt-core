<?php

namespace Wovosoft\LaravelLetsencryptCore\Utils;

use GuzzleHttp\Client;
use GuzzleHttp\Exception\RequestException;

class Cpanel
{
    public function process()
    {
        // cPanel credentials and server details
        $cpanelHost = 'https://yourcpaneldomain:2083';
        $cpanelUser = 'your_cpanel_username';
        $cpanelApiToken = 'your_cpanel_api_token'; // Better than using password
        $domain = 'sub.example.com';
        $cert = "-----BEGIN CERTIFICATE-----\nYourPublicCert\n-----END CERTIFICATE-----";
        $key = "-----BEGIN PRIVATE KEY-----\nYourPrivateKey\n-----END PRIVATE KEY-----";
        $cabundle = "-----BEGIN CERTIFICATE-----\nYourCABundle\n-----END CERTIFICATE-----"; // Optional

        // Initialize Guzzle Client
        $client = new Client([
            'base_uri' => $cpanelHost,
            'headers' => [
                'Authorization' => 'cpanel ' . $cpanelUser . ':' . $cpanelApiToken,
            ],
            'verify' => false // Disable SSL verification if you're using self-signed SSL for testing
        ]);

        try {
            // Send the API request to install SSL
            $response = $client->post('/execute/SSL/install_ssl', [
                'form_params' => [
                    'domain' => $domain,
                    'cert' => $cert,
                    'key' => $key,
                    'cabundle' => $cabundle,
                ]
            ]);

            // Check if the request was successful
            $responseBody = json_decode($response->getBody()->getContents(), true);

            if ($responseBody['status'] === 1) {
                echo 'SSL Certificate installed successfully!';
            } else {
                echo 'Error installing SSL: ' . $responseBody['errors'][0];
            }
        } catch (RequestException $e) {
            echo 'Error: ' . $e->getMessage();
        }
    }
}




