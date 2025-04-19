## SwiftEdDSA

SwiftEdDSA implements the EdDSA digital signature algorithm as defined in RFC 8032.
It is based on the Edwards 25519 and Edwards 448 elliptic curves.

SwiftEdDSA functionality:

* Create public and private keys
* Sign messages - deterministically or non-deterministically
* Verify signatures

SwiftEdDSA requires Swift 5.0. It also requires that the `Int` and `UInt` types be 64 bit types.

Its documentation is build with the DocC plugin and published on GitHub Pages at this location:

https://leif-ibsen.github.io/SwiftEdDSA/documentation/swifteddsa

The documentation is also available in the *SwiftEdDSA.doccarchive* file.

The KAT test vectors come from NIST ACVP-server version 1.1.0.38.
