# ``SwiftEdDSA``

## Overview

SwiftEdDSA implements the EdDSA digital signature algorithm as defined in RFC 8032.  
It is based on the Edwards 25519 and Edwards 448 elliptic curves.

SwiftEdDSA functionality:

* Create public and private keys
* Sign messages - deterministically or non-deterministically
* Verify signatures

> Important:
SwiftEdDSA requires Swift 5.0. It also requires that the `Int` and `UInt` types be 64 bit types.

## Topics

- <doc:Usage>
- <doc:CreatingKeys>
- <doc:LoadingKeys>
- <doc:SignVerify>
- <doc:CryptoKit>
- <doc:Performance>
- <doc:Dependencies>
- <doc:References>
