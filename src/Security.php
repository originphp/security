<?php

/**
 * OriginPHP Framework
 * Copyright 2018 - 2019 Jamiel Sharief.
 *
 * Licensed under The MIT License
 * The above copyright notice and this permission notice shall be included in all copies or substantial
 * portions of the Software.
 *
 * @copyright   Copyright (c) Jamiel Sharief
 * @link        https://www.originphp.com
 * @license     https://opensource.org/licenses/mit-license.php MIT License
 */
declare(strict_types = 1);
namespace Origin\Security;

use InvalidArgumentException;

class Security
{
    const CIPHER = 'AES-256-CBC';

    /**
     * Hashes a string. This is not for passwords.
     *
     * @param string $string
     * @param array $options options keys are
     * - pepper: (default:null). Set a string to use as a pepper
     * - type: (default:sha256)
     * @return string
     */
    public static function hash(string $string, array $options = []): string
    {
        $options += ['pepper' => null, 'type' => 'sha256'];
       
        if (is_string($options['pepper'])) {
            $string = $options['pepper'] . $string;
        }

        $algorithm = strtolower($options['type']);
        if (! in_array($algorithm, hash_algos())) {
            throw new InvalidArgumentException('Invalid hashing algorithm');
        }

        return hash($algorithm, $string);
    }

    /**
     * Hashes a password using the current best practice which is Bcrypt
     *
     * @param string $password
     * @return string
     */
    public static function hashPassword(string $password): string
    {
        return password_hash($password, PASSWORD_DEFAULT);
    }

    /**
     * Verifies a password against a hash created with hashPassword
     *
     * @param string $password
     * @param string $hash
     * @return bool
     */
    public static function verifyPassword(string $password, string $hash): bool
    {
        return password_verify($password, $hash);
    }

    /**
     * Compares two strings are equal in a secure way to prevent timing attacks.
     *
     * @see https://blog.ircmaxell.com/2014/11/its-all-about-time.html
     *
     * @param string $original
     * @param string $compare
     * @return bool
     */
    public static function compare(string $original = null, string $compare = null): bool
    {
        if (! is_string($original) or ! is_string($compare)) {
            return false;
        }

        return hash_equals($original, $compare);
    }

    /**
     * Generates a secure 256 bits (32 bytes) key
     *
     * The size needs to be the same length as the cipher, anything larger will be truncated.
     *
     * @return string
     */
    public static function generateKey(): string
    {
        return bin2hex(random_bytes(16));
    }

    /**
     * Encrypts a string using your key. The key should be secure use. generateKey
     *
     * @see http://php.net/manual/en/function.openssl-encrypt.php
     * @param string $string
     * @param string $key must must be 256 bits (32 bytes)
     * @return string
     */
    public static function encrypt(string $string, string $key) : string
    {
        if (mb_strlen($key) !== 32) {
            throw new InvalidArgumentException('Invalid Key. Key must be 256 bits (32 bytes)');
        }
        $length = openssl_cipher_iv_length(self::CIPHER);
        $iv = random_bytes($length);
        $raw = openssl_encrypt($string, self::CIPHER, $key, OPENSSL_RAW_DATA, $iv);
        $hmac = hash_hmac('sha256', $raw, $key, true);

        return base64_encode($iv . $hmac . $raw);
    }

    /**
     * Decrypts an encrypted string
     *
     * @param string $string
     * @param string $key must must be 256 bits (32 bytes)
     * @return string|null decrypted string
     */
    public static function decrypt(string $string, string $key) : ?string
    {
        if (mb_strlen($key) !== 32) {
            throw new InvalidArgumentException('Invalid Key. Key must be 256 bits (32 bytes)');
        }
        $string = base64_decode($string);
        $length = openssl_cipher_iv_length(self::CIPHER);
        $iv = substr($string, 0, $length);
        $hmac = substr($string, $length, 32);
        $raw = substr($string, $length + 32);
        $expected = hash_hmac('sha256', $raw, $key, true);
       
        if (static::compare($expected, $hmac)) {
            $decrypted = openssl_decrypt($raw, self::CIPHER, $key, OPENSSL_RAW_DATA, $iv);
            if ($decrypted) {
                return $decrypted;
            }
        }

        return null;
    }

    /**
     * Generates a cryptographically secure random hex string with a length 18.
     * Alias for hex with higher default value.
     *
     * @param integer $length 18
     * @return string
     */
    public static function random(int $length = 18) : string
    {
        return static::hex($length);
    }

    /**
     * Generates a cryptographically secure random string that can be used for a unique id.
     *
     * It is designed to be memory & diskspace efficient yet at the same time be unique enough
     * to not have to check the database. This is a solution where you are not required to use a
     * UUID and a user does not need to type.
     *
     * @see https://en.wikipedia.org/wiki/Birthday_problem
     *
     * @param integer $length default 16
     * @return string
     */
    public static function uid(int $length = 16) : string
    {
        return static::base62($length);
    }

    /**
     * Generates a UUID (Universally Unique IDentifier). By default it generates a
     * random UUID (version 4), but if you pass the timestamp option key or provide a
     * MAC address then it will generate a UUID version 1.
     *
     * @param array $options The options array supports the following keys
     *   - macAddress: set to true to use the MAC address (linux) and generate a UUID version 1. If it can't get a MAC address
     * will generate a random one. You can also set the MAC address manually.
     * @return string
     */
    public static function uuid(array $options = []) : string
    {
        $options += ['macAddress' => null];
        if ($options['macAddress']) {
            if ($options['macAddress'] === true) {
                $options['macAddress'] = static::macAddress() ?: bin2hex(random_bytes(6));
            }

            return static::uuidv1($options['macAddress']);
        }

        return static::uuidv4();
    }

    /**
     * Gets the MAC address on Linux systems which can be used with security features
     *
     * @return string
     */
    public static function macAddress() : ?string
    {
        $macAddress = null;
        if (strtoupper(php_uname('s')) === 'LINUX') {
            $files = glob('/sys/class/net/*/address', GLOB_NOSORT);
            foreach ($files as $file) {
                $contents = trim(file_get_contents($file));
                if ($contents !== '00:00:00:00:00:00' and preg_match('/^([0-9a-f]{2}:){5}[0-9a-f]{2}$/', $contents)) {
                    $macAddress = $contents;
                    break;
                }
            }
        }
       
        return null;
    }

    /**
    * Generates a random hex string
    *
    * @param integer $length
    * @return string
    */
    public static function hex(int $length = 16) : string
    {
        $characters = '0123456789abcdef';

        return static::generateRandomString($length, $characters);
    }

    /**
     * Generates a random base36 string
     *
     * @param integer $length
     * @return string
     */
    public static function base36(int $length = 16) : string
    {
        $characters = '0123456789abcdefghijklmnopqrstuvwxyz';

        return static::generateRandomString($length, $characters);
    }

    /**
     * Generates a random base58 string
     *
     * @param integer $length
     * @return string
     */
    public static function base58(int $length = 16) : string
    {
        $characters = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

        return static::generateRandomString($length, $characters);
    }

    /**
    * Generates a random base62 string
    *
    * @param integer $length
    * @return string
    */
    public static function base62(int $length = 16) : string
    {
        $characters = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';

        return static::generateRandomString($length, $characters);
    }

    /**
    * Generates a random base64 string
    *
    * @param integer $length
    * @param boolean $urlSafe use -_ instead of +/
    * @return string
    */
    public static function base64(int $length = 16, bool $urlSafe = false) : string
    {
        $characters = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
        $characters .= ($urlSafe === false) ? '+/' : '-_';

        return static::generateRandomString($length, $characters);
    }

    /**
     * Generates a UUID version 4 - Random
     *
     * @return string
     */
    private static function uuidv4() : string
    {
        return implode('-', [
            bin2hex(random_bytes(4)),
            bin2hex(random_bytes(2)),
            bin2hex(chr((ord(random_bytes(1)) & 0x0F) | 0x40)) . bin2hex(random_bytes(1)),
            bin2hex(chr((ord(random_bytes(1)) & 0x3F) | 0x80)) . bin2hex(random_bytes(1)),
            bin2hex(random_bytes(6)),
        ]);
    }

    /**
     * Generates a UUID version 1 - Sequential/Timestamp based
     *
     * @param string $macAddress e.g. 00:0a:95:9d:68:16
     * @return string
     */
    private static function uuidv1(string $macAddress) : string
    {
        $macAddress = str_replace([':', '-'], '', $macAddress);
        if (strlen($macAddress) !== 12 or ctype_xdigit($macAddress) === false) {
            throw new InvalidArgumentException('Invalid MAC address');
        }

        $sequence = random_int(0, 0x3fff); // Not using a stable storage. (RFC 4122 - Section 4.2.1.1)
      
        // Calculate time
        $time = gettimeofday();
        $uuidTime = ($time['sec'] * 10000000) + ($time['usec'] * 10) + 0x01b21dd213814000;

        $timeLow = sprintf('%08x', $uuidTime & 0xffffffff);
        $timeMid = sprintf('%04x', ($uuidTime >> 32) & 0xffff);
        $timeHi = sprintf('%04x', ($uuidTime >> 48) & 0x0fff);
     
        // Apply Version
        $timeHi = hexdec($timeHi) & 0x0fff;
        $timeHi &= ~(0xf000);
        $timeHi |= 1 << 12;

        $sequenceHi = $sequence >> 8;
        $sequenceHi = $sequenceHi & 0x3f;
        $sequenceHi &= ~(0xc0);
        $sequenceHi |= 0x80;

        return vsprintf('%08s-%04s-%04s-%02s%02s-%012s', [
            $timeLow,
            $timeMid,
            sprintf('%04x', $timeHi),
            sprintf('%02x', $sequenceHi),
            sprintf('%02x', $sequence & 0xff),
            $macAddress
        ]);
    }

    /**
     * Random string generator
     *
     * @param integer $length
     * @param string $characters
     * @return string
     */
    private static function generateRandomString(int $length, string  $characters) : string
    {
        $max = strlen($characters) - 1;
        $out = '';
        for ($i = 0; $i < $length; $i++) {
            $out .= $characters[random_int(0, $max)];
        }

        return $out;
    }
}
