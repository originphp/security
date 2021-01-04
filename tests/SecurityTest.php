<?php
/**
 * OriginPHP Framework
 * Copyright 2018 - 2021 Jamiel Sharief.
 *
 * Licensed under The MIT License
 * The above copyright notice and this permission notice shall be included in all copies or substantial
 * portions of the Software.
 *
 * @copyright   Copyright (c) Jamiel Sharief
 * @link        https://www.originphp.com
 * @license     https://opensource.org/licenses/mit-license.php MIT License
 */

namespace Origin\Test\Security;

use Origin\Security\Security;
use \InvalidArgumentException;

class SecurityTest extends \PHPUnit\Framework\TestCase
{
    public function testHash()
    {
        $plain = 'The quick brown fox jumps over the lazy dog';
        $expected = '2fd4e1c67a2d28fced849ee1bb76e7391b93eb12';
       
        $this->assertEquals($expected, Security::hash($plain, ['type' => 'sha1']));
   
        $expected = 'd7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592';
        $this->assertEquals($expected, Security::hash($plain));
        
        $expected = '2a70c8107928b49f2c2b64bac4aacb820aef818b';
        $this->assertEquals($expected, Security::hash($plain, ['type' => 'sha1','pepper' => 'OriginPHP']));

        $this->expectException(InvalidArgumentException::class);
        Security::hash($plain, ['type' => 'unkownHashType']);
    }

    public function testMacAddress()
    {
        if (strtoupper(php_uname('s')) !== 'LINUX') {
            $this->markTestSkipped('This test is for Linux');
        }
        $this->assertRegExp('/^([0-9a-f]{2}:){5}[0-9a-f]{2}$/', Security::macAddress());
    }

    public function testHashPassword()
    {
        $result = Security::hashPassword('secret');
        $this->assertStringContainsString('$2y$10', $result);
    }

    /**
     * @depends testHashPassword
     */
    public function testVerifyPassword()
    {
        $result = Security::hashPassword('secret');
        $this->assertTrue(Security::verifyPassword('secret', $result));
    }

    public function testCompare()
    {
        $expected = crypt('12345', '$2a$07$areallylongstringthatwillbeusedasasalt$');
        $correct = crypt('12345', '$2a$07$areallylongstringthatwillbeusedasasalt$');
        $incorrect = crypt('67890', '$2a$07$areallylongstringthatwillbeusedasasalt$');

        $this->assertTrue(Security::compare($expected, $correct));
        $this->assertFalse(Security::compare($expected, $incorrect));
        $this->assertFalse(Security::compare(null, ''));
    }

    public function testEncryptDecrypt()
    {
        $plain = 'The quick brown fox jumps over the lazy dog';
        $key = '58024d70eb647a3d0654d5211af2ebfd';
  
        $encrypted = Security::encrypt($plain, $key);
        $decrypted = Security::decrypt($encrypted, $key);
        $this->assertEquals($plain, $decrypted);
        $this->assertNull(Security::decrypt($encrypted, str_replace('7', 'a', $key))); // test wrong key

        $this->expectException(InvalidArgumentException::class);
        Security::decrypt($encrypted, $key.'x');
    }

    public function testEncryptInvalidKey()
    {
        $this->expectException(InvalidArgumentException::class);
        Security::encrypt('foo', 'secret');
    }

    public function testDecryptInvalidKey()
    {
        $key = '58024d70eb647a3d0654d5211af2ebfd';

        $encrypted = Security::encrypt('foo', $key);
        $this->expectException(InvalidArgumentException::class);
        Security::decrypt($encrypted, 'secret');
    }

    public function testGenerateKey()
    {
        $this->assertRegExp('/^[a-zA-Z0-9]{32}+$/', Security::generateKey());
    }

    public function testEncryptInvalidKeyLength()
    {
        $this->expectException(InvalidArgumentException::class);
        Security::encrypt('text', 'invalidkey');
    }

    public function testDecryptInvalidKeyLength()
    {
        $this->expectException(InvalidArgumentException::class);
        Security::decrypt('text', 'invalidkey');
    }

    public function testUUID()
    {
        $this->assertRegExp(
            '/\b[0-9a-f]{8}\b-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-\b[0-9a-f]{12}\b/',
            Security::uuid()
        );

        $this->assertRegExp(
            '/\b[0-9a-f]{8}\b-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-\b[0-9a-f]{12}\b/',
            Security::uuid(['timestamp' => true])
        );

        $this->assertRegExp(
            '/\b[0-9a-f]{8}\b-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-\b[0-9a-f]{12}\b/',
            Security::uuid(['macAddress' => true])
        );

        $this->assertRegExp(
            '/\b[0-9a-f]{8}\b-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-\b[0-9a-f]{12}\b/',
            Security::uuid(['macAddress' => '00:01:01:00:00:00'])
        );

        $this->expectException(InvalidArgumentException::class);
        Security::uuid(['macAddress' => 'example.com']);
    }

    public function testUid()
    {
        $this->assertRegExp('/^[a-zA-Z0-9]{16}$/', Security::uid());
        $this->assertRegExp('/^[a-zA-Z0-9]{18}$/', Security::uid(18));
    }

    public function testRandom()
    {
        $this->assertRegExp('/^[a-f0-9]{16}$/', Security::random());
        $this->assertRegExp('/^[a-f0-9]{21}$/', Security::random(21));
    }

    public function testHex()
    {
        $this->assertRegExp('/^[a-f0-9]{16}$/', Security::hex());
        $this->assertRegExp('/^[a-f0-9]{32}$/', Security::hex(32));
    }
    public function testBase64()
    {
        $regex = '/^[A-Za-z0-9+\/]';
        $this->assertRegExp($regex . '{16}$/', Security::base64());
        $this->assertRegExp($regex . '{32}$/', Security::base64(32));

        $regex = '/^[-A-Za-z0-9_-]';
        $this->assertRegExp($regex . '{64}$/', Security::base64(64, true));
    }

    public function testBase62()
    {
        $chars = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
        $this->assertRegExp('/^[' . $chars . ']{64}$/', Security::base62(64));
    }

    public function testBase58()
    {
        $chars = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
        $this->assertRegExp('/^[' . $chars . ']{64}$/', Security::base58(64));
    }

    public function testBase36()
    {
        $chars = '0123456789abcdefghijklmnopqrstuvwxyz';
        $this->assertRegExp('/^[' . $chars . ']{64}$/', Security::base36(64));
    }
}
