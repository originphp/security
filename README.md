# Security

![license](https://img.shields.io/badge/license-MIT-brightGreen.svg)
[![build](https://travis-ci.org/originphp/security.svg?branch=master)](https://travis-ci.org/originphp/security)
[![coverage](https://coveralls.io/repos/github/originphp/security/badge.svg?branch=master)](https://coveralls.io/github/originphp/security?branch=master)

The `Security` library provides various function related to security such as hashing, encryption, decryption.

## Installation

To install this package

```linux
$ composer require originphp/security
```

## Hashing

### Hashing Strings (Not Passwords)

The default hashing algorithm used is `sha256`.

To hash a string (not password)

```php
use Origin\Security\Security;
$hashed = Security::hash('foo');
```

To hash a string with a pepper (also incorrectly known as salt).

```php
$hashed = Security::hash('foo',['pepper'=>'A random string']);
```

To change the hashing type

```php
$hashed = Security::hash('foo',['type'=>'sha1']);
```

For a full list of supported algorithms

```php
$list = hash_algos()
```

### Hashing Passwords

The Security utility hashes passwords using best practices, currently this is `bcrypt` which is considered
very secure.

```php
$hashed = Security::hashPassword('secret');
```

To verify the password is correct

```php
$hashed = Security::hashPassword('secret');
$bool = Security::verifyPassword($input,$hashed); // input is user inputted password
```

## Encryption

### Generating a Secure Key

To encrypt and decrypt a string you will need a key, you can generate a random secure key.

```php
use Origin\Security\Security;
$key = Security::generateKey(); // 33d80476167cc95c363bf7df3c95e1d1
```

The key length must be 32 bytes (256 bits) to use with the encryption decryption functions.

### Encrypting Text

To encrypt a string

```php
use Origin\Security\Security;
$key = '33d80476167cc95c363bf7df3c95e1d1';
$encrypted = Security::encrypt('foo',$key);
```

### Decrypting Text

To decrypt an encrypted string

```php
use Origin\Security\Security;
$key = '33d80476167cc95c363bf7df3c95e1d1';
$encrypted = 'ohRRdAydx+4wfOd7Vm+LHmmV9zBH+3r0WLQylyPMPu2RvCjX9FVgoeUBZuLYBTLM4x9NeZX7U0bUvE1bucATSQ==';
$plain = Security::decrypt($encrypted,$key);
```

## Random Strings

To generate a cryptographically secure random string, the default length is 18. It is an alias for hex but with higher default length.

```php
$randomString = Security::random(); // 5f31ecf661dabb04dc
```

### Different Encodings

You can generate random strings with different encoding.

```php
$hex = Security::hex(); // gpgf67ezotl06wqs
$base36 = Security::base36(); // 13owqvwcgb426rvq
$base58 = Security::base58(); // SyqBFAtGfNxZkZMQ
$base62 = Security::base62(); // oc1eIfAHKWWt5zrO
$base64 = Security::base64(); // v3xsI6O+g6LsuY4+
// url safe
$base64 = Security::base64(16,true); // YPT9rp-i6jqXWCvA
```

## UID

If you need to generate a unique id, and don't need to use a UUID, then the UID method provides a more memory and disk space efficient way when working with unique ids.

> If you are generating a API token or another form of string that a user might need to type in, then use `Security::random` or `Security::uuid` instead since these use lower case characters.

To generate a cryptographically secure unique id (UID) with the default length of 16.

```php
$uid = Security::uid(); // O64cjBxfz2JPhyCQ
```

### UUID

The Security class can generate both version 4 and version 1 UUIDs.

To generate a random UUID (version 4)

```php
$uid = Security::uuid(); // 38c67382-d3ab-4430-a27e-0c719813c09f
```

For a version 1 UUID, set MAC address to true, this will find the MAC address on Linux systems or generate a random
one if it can not get this.

```php
$uid = Security::uuid(['macAddress'=>true]); // ac337932-e4e5-11e9-928f-8bda39fe8887
```

You can also set the MAC address manually.

```php
$uid = Security::uuid(['macAddress'=>'00:0a:95:9d:68:16']); // 769c6fa4-e4e5-11e9-b8d5-000a959d6816
```