# ``SwiftEdDSA/Ed``

## Overview

Ed exists to provide a namespace. It contains static methods for keypair generation and validation
and for ASN1 signature encoding and decoding. There is no Ed instances.

## Topics

### Methods

- ``makeKeyPair(kind:)``
- ``keyPairIsValid(r:s:)``
- ``encodeSignature(signature:)``
- ``decodeSignature(signature:)``

### Curve Kinds

- ``Kind``

### Exceptions

- ``Ex``
