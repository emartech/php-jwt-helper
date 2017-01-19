<?php

use Emartech\Jwt\Jwt;

class JwtTest extends PHPUnit_Framework_TestCase
{
    /**
     * @test
     * @expectedException \InvalidArgumentException
     */
    public function parseHeader_MalformedHeader_itCheckAuthorizationHeaderFormat()
    {
        $jwt = new Jwt('irrelevant_secret');
        $jwt->parseHeader("malformed header");
    }

    /**
     * @test
     */
    public function parseHeader_AuthorizationHeaderProvided_itShouldParseAuthorizationHeader()
    {
        $jwt = new Jwt('secret_key');
        $payload = (object)array('payload' => 'data');
        $this->assertEquals($payload, $jwt->parseHeader("Bearer ".Firebase\JWT\JWT::encode($payload, 'secret_key')));
    }

    /**
     * @test
     */
    public function parseHeader_BadAuthorizationHeaderProvided_itShouldParseAuthorizationHeader()
    {
        $jwt = new Jwt('secret_key');

        try
        {
            $jwt->parseHeader("Bearer ".Firebase\JWT\JWT::encode([], 'wrong_key'));
        } catch (\Firebase\JWT\SignatureInvalidException $ex)
        {
            $this->assertEquals('Signature verification failed', $ex->getMessage());
            return;
        }

        $this->fail('Exception expected.');
    }
}
