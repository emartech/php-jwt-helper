<?php

use Emartech\Jwt\Jwt;
use Emartech\TestHelper\BaseTestCase;

class JwtTest extends BaseTestCase
{
    /**
     * @test
     */
    public function parseHeader_MalformedHeader_itCheckAuthorizationHeaderFormat()
    {
        $this->assertExceptionThrown(InvalidArgumentException::class, function () {
            (new Jwt('irrelevant_secret'))->parseHeader("malformed header");
        });
    }

    /**
     * @test
     */
    public function parseHeader_AuthorizationHeaderProvided_itShouldParseAuthorizationHeader()
    {
        $jwt = new Jwt('secret_key');
        $payload = (object)array('payload' => 'data');
        $this->assertEquals($payload, $jwt->parseHeader("Bearer " . Firebase\JWT\JWT::encode($payload, 'secret_key')));
    }

    /**
     * @test
     */
    public function parseHeader_BadAuthorizationHeaderProvided_itShouldParseAuthorizationHeader()
    {
        $jwt = new Jwt('secret_key');

        try {
            $jwt->parseHeader("Bearer " . Firebase\JWT\JWT::encode([], 'wrong_key'));
        } catch (\Firebase\JWT\SignatureInvalidException $ex) {
            $this->assertEquals('Signature verification failed', $ex->getMessage());
            return;
        }

        $this->fail('Exception expected.');
    }
}
