# ``SwiftEdDSA``

Edwards-Curve Digital Signature Algorithm

## Overview

SwiftEdDSA implements the EdDSA digital signature algorithm as defined in [RFC 8032].  
It is based on the Edwards 25519 and Edwards 448 elliptic curves.

SwiftEdDSA functionality:

* Create public and private keys
* Sign messages - deterministically or non-deterministically
* Verify signatures

### Create new keys

**To create a new private key**

```swift
// Curve Ed25519
let privKey = PrivateKey(kind: .ed25519)

// Curve Ed448
let privKey = PrivateKey(kind: .ed448)
```

**To create a new key pair**

```swift
// Curve Ed25519 key pair
let (pubKey, privKey) = Ed.makeKeyPair(kind: .ed25519)

// Curve Ed448 key pair
let (pubKey, privKey) = Ed.makeKeyPair(kind: .ed448)
```

**To create a public key corresponding to a private key**

```swift
let pubKey = PublicKey(privateKey: privKey)
```

### Load keys from their PEM encoding

```swift
import SwiftEdDSA

let pubPEM =
"""
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA59XU+uLDn3fVTDfLZXJnITqbYoPwxSjfUehk8/E9stI=
-----END PUBLIC KEY-----
"""
let privPEM =
"""
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIHZN8jGTAPTSZoZO9PWDhTgRDrO5Q6cW1IWCxcsmoZ7X
-----END PRIVATE KEY-----
"""

let pub = try PublicKey(pem: pubPEM)
let priv = try PrivateKey(pem: privPEM)

print(pub)
print(priv)
```
giving:
```swift
Sequence (2):
    Sequence (1):
       Object Identifier: 1.3.101.112
    Bit String (256): 11100111 11010101 11010100 11111010 11100010 11000011 10011111 01110111 11010101 01001100 00110111 11001011 01100101 01110010 01100111 00100001 00111010 10011011 01100010 10000011 11110000 11000101 00101000 11011111 01010001 11101000 01100100 11110011 11110001 00111101 10110010 11010010

Sequence (3):
    Integer: 0
    Sequence (1):
       Object Identifier: 1.3.101.112
    Octet String (34): 04 20 76 4d f2 31 93 00 f4 d2 66 86 4e f4 f5 83 85 38 11 0e b3 b9 43 a7 16 d4 85 82 c5 cb 26 a1 9e d7
```

### Sign a message and verify a signature

```swift
import SwiftEdDSA

let pubPEM =
"""
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA59XU+uLDn3fVTDfLZXJnITqbYoPwxSjfUehk8/E9stI=
-----END PUBLIC KEY-----
"""
let privPEM =
"""
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIHZN8jGTAPTSZoZO9PWDhTgRDrO5Q6cW1IWCxcsmoZ7X
-----END PRIVATE KEY-----
"""

let pubKey = try PublicKey(pem: pubPEM)
let privKey = try PrivateKey(pem: privPEM)

let msg = Bytes("Hi, there".utf8)

// Sign deterministically in pure operation mode
let deterministicSig = try privKey.sign(message: msg, deterministic: true)

// Sign non-deterministically in pure operation mode
let nonDeterministicSig = try privKey.sign(message: msg, deterministic: false)

print("Verified:", pubKey.verify(signature: deterministicSig, message: msg))
print("Verified:", pubKey.verify(signature: nonDeterministicSig, message: msg))

// Alternatively, use pre-hash operation mode

// Sign deterministically in pre-hash operation mode
let deterministicSigPH = try privKey.signPH(message: msg, deterministic: true)

// Sign non-deterministically in pre-hash operation mode
let nonDeterministicSigPH = try privKey.signPH(message: msg, deterministic: false)

print("Verified:", pubKey.verifyPH(signature: deterministicSigPH, message: msg))
print("Verified:", pubKey.verifyPH(signature: nonDeterministicSigPH, message: msg))

// See the signatures as ASN1
try print(Ed.encodeSignature(signature: deterministicSig))
try print(Ed.encodeSignature(signature: nonDeterministicSig))
```
giving (for example):

```swift
Verified: true
Verified: true
Verified: true
Verified: true
Sequence (2):
  Octet String (32): 36 98 9e c1 34 50 2c d6 f6 c1 9b 59 9d 0b 27 19 02 b7 4f 6e 2d 69 47 6a af 42 55 2a 67 c3 05 04
  Octet String (32): 80 a1 9b 5d 44 08 b8 21 31 a9 d7 ae f2 2e 55 ce 91 15 07 dd 3c b3 cc 9a a3 3c f2 f9 3b b1 95 0e

Sequence (2):
  Octet String (32): 81 7e 15 db 12 f3 a8 31 5e 7b e6 aa 2f d5 a0 ee b9 a1 b2 04 d9 d2 c8 0d 88 cf 1e 0f a7 75 7a 42
  Octet String (32): 12 5c 9e 89 20 7b ad 79 fa f0 c1 f4 89 a1 72 01 ae f9 91 a6 f6 0e f6 f4 3f 9e 2e fe 5d 28 f2 0a
```

### Usage

To use SwiftEdDSA, in your project *Package.swift* file add a dependency like

```swift
dependencies: [
  .package(url: "https://github.com/leif-ibsen/SwiftEdDSA", from: "4.0.0"),
]
```
SwiftEdDSA itself depends on the [ASN1](https://leif-ibsen.github.io/ASN1/documentation/asn1), [BigInt](https://leif-ibsen.github.io/BigInt/documentation/bigint) and [Digest](https://leif-ibsen.github.io/Digest/documentation/digest) packages

```swift
dependencies: [
  .package(url: "https://github.com/leif-ibsen/ASN1", from: "2.7.0"),
  .package(url: "https://github.com/leif-ibsen/BigInt", from: "1.21.0"),
  .package(url: "https://github.com/leif-ibsen/Digest", from: "1.13.0"),
],
```

> Important:
SwiftEdDSA requires Swift 5.0. It also requires that the `Int` and `UInt` types be 64 bit types.

## Topics

### Classes

- ``SwiftEdDSA/Ed``
- ``SwiftEdDSA/PrivateKey``
- ``SwiftEdDSA/PublicKey``

### Type Aliases

- ``SwiftEdDSA/Byte``
- ``SwiftEdDSA/Bytes``

### Additional Information

- <doc:AboutEdDSA>
- <doc:Performance>
- <doc:CryptoKit>
- <doc:References>

