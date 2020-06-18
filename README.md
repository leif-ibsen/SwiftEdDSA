<h2><b>Description</b></h2>

SwiftEdDSA is a Swift implementation of the EdDSA digital signature algorithm. It is based on the Edwards 25519 and Edwards 448 elliptic curves.
SwiftEdDSA has functionality to create public and private keys, to sign messages, and to verify signatures.

<h2><b>Usage</b></h2>
In your project Package.swift file add a dependency like<br/>

	  dependencies: [
	  .package(url: "https://github.com/leif-ibsen/SwiftEd", from: "1.0.0"),
	  ]

<h2><b>Key Generation</b></h2>
<h3><b>To create a new private key instance</b></h3>

    let privKey1 = PrivateKey(kind: .ed25519)
    let privKey2 = PrivateKey(kind: .ed448)

<h3><b>To create an existing private key instance from its bytes</b></h3>

    let privBytes: Bytes = [0x6c, 0x82, 0xa5, 0x62, 0xcb, 0x80, 0x8d, 0x10, 0xd6, 0x32, 0xbe, 0x89, 0xc8, 0x51, 0x3e,
        0xbf, 0x6c, 0x92, 0x9f, 0x34, 0xdd, 0xfa, 0x8c, 0x9f, 0x63, 0xc9, 0x96, 0x0e, 0xf6,
        0xe3, 0x48, 0xa3, 0x52, 0x8c, 0x8a, 0x3f, 0xcc, 0x2f, 0x04, 0x4e, 0x39, 0xa3, 0xfc,
        0x5b, 0x94, 0x49, 0x2f, 0x8f, 0x03, 0x2e, 0x75, 0x49, 0xa2, 0x00, 0x98, 0xf9, 0x5b]
    let privKey = try PrivateKey(s: privBytes)

<h3><b>To create a new key pair</b></h3>

    let (pubKey1, privKey1) = Ed.makeKeyPair(kind: .ed25519)
    let (pubKey2, privKey2) = Ed.makeKeyPair(kind: .ed448)

<h3><b>To create a public key instance that corresponds to an existing private key</b></h3>

    let pubKey = PublicKey(privateKey: privKey)

<h3><b>To create a public key instance from its bytes</b></h3>

    let pubBytes: Bytes = [0x5f, 0xd7, 0x44, 0x9b, 0x59, 0xb4, 0x61, 0xfd, 0x2c, 0xe7, 0x87, 0xec, 0x61, 0x6a, 0xd4,
        0x6a, 0x1d, 0xa1, 0x34, 0x24, 0x85, 0xa7, 0x0e, 0x1f, 0x8a, 0x0e, 0xa7, 0x5d, 0x80,
        0xe9, 0x67, 0x78, 0xed, 0xf1, 0x24, 0x76, 0x9b, 0x46, 0xc7, 0x06, 0x1b, 0xd6, 0x78,
        0x3d, 0xf1, 0xe5, 0x0f, 0x6c, 0xd1, 0xfa, 0x1a, 0xbe, 0xaf, 0xe8, 0x25, 0x61, 0x80]
    let pubKey = try PublicKey(r: pubBytes)

<h3><b>To check if a keypair is valid</b></h3>

    let valid: Bool = Ed.keyPairIsValid(r: pubBytes, s: privBytes)

<h3><b>To work with PEM encoding and ASN1</b></h3>

    let privPem =
    """
    -----BEGIN PRIVATE KEY-----
    MC4CAQAwBQYDK2VwBCIEIOt4JdgMPOLaGxdbZckz7ARIeuZgTvoKpUt4jdci/3cI
    -----END PRIVATE KEY-----
    """
    let privKey = try PrivateKey(pem: privPem)
    print(privKey)

giving

    Sequence (3):
      Integer: 0
      Sequence (1):
        Object Identifier: 1.3.101.112
      Octet String (34): 04 20 eb 78 25 d8 0c 3c e2 da 1b 17 5b 65 c9 33 ec 04 48 7a e6 60 4e fa 0a a5 4b 78 8d d7 22 ff 77 08

<h2><b>Sign and Verify</b></h2>

    let msg = Bytes("The message".utf8)
    let pubBytes: Bytes = [0x5f, 0xd7, 0x44, 0x9b, 0x59, 0xb4, 0x61, 0xfd, 0x2c, 0xe7, 0x87, 0xec, 0x61, 0x6a, 0xd4,
        0x6a, 0x1d, 0xa1, 0x34, 0x24, 0x85, 0xa7, 0x0e, 0x1f, 0x8a, 0x0e, 0xa7, 0x5d, 0x80,
        0xe9, 0x67, 0x78, 0xed, 0xf1, 0x24, 0x76, 0x9b, 0x46, 0xc7, 0x06, 0x1b, 0xd6, 0x78,
        0x3d, 0xf1, 0xe5, 0x0f, 0x6c, 0xd1, 0xfa, 0x1a, 0xbe, 0xaf, 0xe8, 0x25, 0x61, 0x80]
    let privBytes: Bytes = [0x6c, 0x82, 0xa5, 0x62, 0xcb, 0x80, 0x8d, 0x10, 0xd6, 0x32, 0xbe, 0x89, 0xc8, 0x51, 0x3e,
        0xbf, 0x6c, 0x92, 0x9f, 0x34, 0xdd, 0xfa, 0x8c, 0x9f, 0x63, 0xc9, 0x96, 0x0e, 0xf6,
        0xe3, 0x48, 0xa3, 0x52, 0x8c, 0x8a, 0x3f, 0xcc, 0x2f, 0x04, 0x4e, 0x39, 0xa3, 0xfc,
        0x5b, 0x94, 0x49, 0x2f, 0x8f, 0x03, 0x2e, 0x75, 0x49, 0xa2, 0x00, 0x98, 0xf9, 0x5b]
    print("Key pair is valid:", Ed.keyPairIsValid(r: pubBytes, s: privBytes))
    do {
        let pubKey = try PublicKey(r: pubBytes)
        let privKey = try PrivateKey(s: privBytes)
        let sig = try privKey.sign(message: msg)
        print("Verified:", pubKey.verify(signature: sig, message: msg))
    } catch {
        print("\(error)")
    }

giving

    Key pair is valid: true
    Verified: true

<h2><b>Performance</b></h2>
The signature generation and verification time and the key generation time
was measured on a MacBook Pro 2018, 2,2 GHz 6-Core Intel Core i7. The results are shown below:
<table width="80%">
<tr><th align="left" width="34%">Operation</th><th align="right" width="33%">Ed25519</th><th align="right" width="33%">Ed448</th></tr>
<tr><td>Sign</td><td align="right">3.4 mSec</td><td align="right">7.8 mSec</td></tr>
<tr><td>Verify</td><td align="right">4.0 mSec</td><td align="right">10 mSec</td></tr>
<tr><td>Public Key Generation</td><td align="right">11 mSec</td><td align="right">22 mSec</td></tr>
<tr><td>Private Key Generation</td><td align="right">0.67 uSec</td><td align="right">0.61 uSec</td></tr>
</table>

The public key constructor computes and caches information that subsequently speed-up signature verification.
If the same public key is to be used for many signature verifications, it is more efficient to use the same key instance for all verifications,
rather than generate a new instance for each verification.

<h2><b>Dependencies</b></h2>

SwiftEdDSA requires Swift 5.0.

The SwiftEdDSA package depends on the ASN1 and BigInt packages

    dependencies: [
        .package(url: "https://github.com/leif-ibsen/ASN1", from: "1.2.1"),
        .package(url: "https://github.com/leif-ibsen/BigInt", from: "1.1.2"),
    ],

<h2><b>References</b></h2>

Algorithms from the following books and papers have been used in the implementation.
There are references in the source code where appropriate.

<ul>
<li>[GUIDE] - Hankerson, Menezes, Vanstone: Guide to Elliptic Curve Cryptography. Springer 2004</li>
<li>[RFC-8032] - Edwards-Curve Digital Signature Algorithm (EdDSA), January 2017</li>
</ul>
