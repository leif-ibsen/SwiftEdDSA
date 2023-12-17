<h2><b>SwiftEdDSA</b></h2>
<h3><b>Contents:</b></h3>
<ul>
<li><a href="#use">Usage</a></li>
<li><a href="#newkeys">Creating New Keys</a></li>
<li><a href="#load">Loading Existing Keys</a></li>
<li><a href="#sign">Sign and Verify</a></li>
<li><a href="#comp">CryptoKit Compatibility</a></li>
<li><a href="#perf">Performance</a></li>
<li><a href="#dep">Dependencies</a></li>
<li><a href="#ref">References</a></li>
</ul>

SwiftEdDSA implements the EdDSA digital signature algorithm as defined in RFC 8032.
It is based on the Edwards 25519 and Edwards 448 elliptic curves.
SwiftEdDSA has functionality to create public and private keys, to sign messages, and to verify signatures.

<h2 id="use"><b>Usage</b></h2>
In your project Package.swift file add a dependency like<br/>

	  dependencies: [
	  .package(url: "https://github.com/leif-ibsen/SwiftEdDSA", from: "3.0.0"),
	  ]

<h2 id="newkeys"><b>Creating New Keys</b></h2>
<h3><b>To create a new private key instance</b></h3>
    // Curve Ed25519
    let privKey = PrivateKey(kind: .ed25519)
    
    // Curve Ed448
    let privKey = PrivateKey(kind: .ed448)
<h3><b>To create a new key pair</b></h3>
    // Curve Ed25519 key pair
    let (pubKey, privKey) = Ed.makeKeyPair(kind: .ed25519)
    
    // Curve Ed448 key pair
    let (pubKey, privKey) = Ed.makeKeyPair(kind: .ed448)
<h2 id="load"><b>Loading Existing Keys</b></h2>
<h3><b>To load keys from their PEM encoding</b></h3>
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
    
giving:

    Sequence (2):
      Sequence (1):
        Object Identifier: 1.3.101.112
      Bit String (256): 11100111 11010101 11010100 11111010 11100010 11000011 10011111 01110111 11010101 01001100 00110111 11001011 01100101 01110010 01100111 00100001 00111010 10011011 01100010 10000011 11110000 11000101 00101000 11011111 01010001 11101000 01100100 11110011 11110001 00111101 10110010 11010010

    Sequence (3):
      Integer: 0
      Sequence (1):
        Object Identifier: 1.3.101.112
      Octet String (34): 04 20 76 4d f2 31 93 00 f4 d2 66 86 4e f4 f5 83 85 38 11 0e b3 b9 43 a7 16 d4 85 82 c5 cb 26 a1 9e d7

<h3><b>To create a public key corresponding to a private key</b></h3>

    let pubKey = PublicKey(privateKey: privKey)
<h2 id="sign"><b>Sign and Verify</b></h2>
<h3><b>To sign and verify a message</b></h3>

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
    let sig = try privKey.sign(message: msg)
    print("Verified:", pubKey.verify(signature: sig, message: msg))

giving:

    Verified: true

<h2 id="comp"><b>Compatibility with Apple's CryptoKit Framework</b></h2>
SwiftEdDSA keys of kind *.ed25519* corresponds to CryptoKit's *Curve25519* keys.
Keys of kind *.ed448* is not supported in CryptoKit.

To convert SwiftEdDSA keys - say *edPriv* and *edPub* to corresponding CryptoKit keys:

    let ckPriv = try CryptoKit.Curve25519.Signing.PrivateKey(rawRepresentation: edPriv.s)
    let ckPub = try CryptoKit.Curve25519.Signing.PublicKey(rawRepresentation: edPub.r)

To convert CryptoKit keys - say *ckPriv* and *ckPub* to corresponding SwiftEdDSA keys:

    let edPriv = try PrivateKey(s: Bytes(ckPriv.rawRepresentation))
    let edPub = try PublicKey(r: Bytes(ckPub.rawRepresentation))

<h2 id="perf"><b>Performance</b></h2>
The signature generation and verification time for a short message and the time it takes to
generate a new private key and to generate a public key from its private key
was measured on an iMac 2021, Apple M1 chip. The results are shown below:
<table width="80%">
<tr><th align="left" width="34%">Operation</th><th align="right" width="33%">Ed25519</th><th align="right" width="33%">Ed448</th></tr>
<tr><td>Sign</td><td align="right">0.8 mSec</td><td align="right">2.1 mSec</td></tr>
<tr><td>Verify</td><td align="right">1.1 mSec</td><td align="right">3.0 mSec</td></tr>
<tr><td>Public Key Generation</td><td align="right">2.8 mSec</td><td align="right">6.6 mSec</td></tr>
<tr><td>Private Key Generation</td><td align="right">0.67 uSec</td><td align="right">0.61 uSec</td></tr>
</table>

The public key constructor computes and caches information that subsequently speed-up signature verification.
If the same public key is to be used for many signature verifications, it is more efficient to use the same key instance for all verifications,
rather than generate a new instance for each verification.

<h2 id="dep"><b>Dependencies</b></h2>

SwiftEdDSA requires Swift 5.0.

The SwiftEdDSA package depends on the ASN1, BigInt and Digest packages

    dependencies: [
        .package(url: "https://github.com/leif-ibsen/ASN1", from: "2.2.0"),
        .package(url: "https://github.com/leif-ibsen/BigInt", from: "1.14.0"),
        .package(url: "https://github.com/leif-ibsen/Digest", from: "1.1.0"),
    ],

<h2 id="ref"><b>References</b></h2>

Algorithms from the following books and papers have been used in the implementation.
There are references in the source code where appropriate.

<ul>
<li>[GUIDE] - Hankerson, Menezes, Vanstone: Guide to Elliptic Curve Cryptography. Springer 2004</li>
<li>[RFC-8032] - Edwards-Curve Digital Signature Algorithm (EdDSA), January 2017</li>
</ul>
