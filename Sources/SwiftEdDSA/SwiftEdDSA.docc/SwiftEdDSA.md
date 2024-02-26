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

// Sign deterministically
let deterministicSig = try privKey.sign(message: msg, deterministic: true)

// Sign non-deterministically
let nonDeterministicSig = try privKey.sign(message: msg, deterministic: false)

print("Verified:", pubKey.verify(signature: deterministicSig, message: msg))
print("Verified:", pubKey.verify(signature: nonDeterministicSig, message: msg))
```
giving:
```swift
Verified: true
Verified: true
```

### Usage

To use SwiftEdDSA, in your project *Package.swift* file add a dependency like

```swift
dependencies: [
  .package(url: "https://github.com/leif-ibsen/SwiftEdDSA", from: "3.3.0"),
]
```

SwiftEdDSA itself depends on the ASN1, BigInt and Digest packages

```swift
dependencies: [
  .package(url: "https://github.com/leif-ibsen/ASN1", from: "2.4.0"),
  .package(url: "https://github.com/leif-ibsen/BigInt", from: "1.16.0"),
  .package(url: "https://github.com/leif-ibsen/Digest", from: "1.3.0"),
],
```

> Important:
SwiftEdDSA requires Swift 5.0. It also requires that the `Int` and `UInt` types be 64 bit types.

## Topics

### Classes

- ``SwiftEdDSA/Ed``
- ``SwiftEdDSA/PrivateKey``
- ``SwiftEdDSA/PublicKey``
- ``SwiftEdDSA/Base64``

### Type Aliases

- ``SwiftEdDSA/Byte``
- ``SwiftEdDSA/Bytes``

### Additional Information

- <doc:CryptoKit>
- <doc:Performance>
- <doc:References>

