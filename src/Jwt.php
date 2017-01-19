<?php

namespace Emartech\Jwt;

class Jwt
{
    const TOKEN_EXPIRY_SECONDS = 300;
    const TOKEN_REGEXP = '[a-zA-Z0-9-_]+.[a-zA-Z0-9-_]+.[a-zA-Z0-9-_]+';
    const LEEWAY_SECONDS = 15;

    private $secretKey;

    /**
     * @var array
     */
    private $allowedAlgorithms;

    public static function create()
    {
        $secretKey = getenv('JWT_SECRET');
        if (!$secretKey) {
            throw new \InvalidArgumentException("No secret key provided.");
        }
        return new self($secretKey);
    }

    public function __construct($secretKey, $allowedAlgorithms = array('HS256'), $leeway = self::LEEWAY_SECONDS)
    {
        $this->secretKey = $secretKey;
        $this->allowedAlgorithms = $allowedAlgorithms;
        $this->leeway = $leeway;
    }

    public function parseHeader($headerValue)
    {
        if (!preg_match('/^Bearer ('.self::TOKEN_REGEXP.')$/', $headerValue, $matches)) {
            throw new \InvalidArgumentException("Malformed header");
        }
        \Firebase\JWT\JWT::$leeway = 15;
        return \Firebase\JWT\JWT::decode($matches[1], $this->secretKey, $this->allowedAlgorithms);
    }

    public function generateToken($data, $expirySeconds = self::TOKEN_EXPIRY_SECONDS)
    {
        $now = time();
        $payload = array(
            "exp" => $now + $expirySeconds,
            "nbf" => $now,
            "data" => $data,
        );
        return \Firebase\JWT\JWT::encode($payload, $this->secretKey);
    }
}
