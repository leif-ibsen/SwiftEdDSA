# ``SwiftEdDSA/PrivateKey``

The private key - either an Ed25519 private key or an Ed448 private key

## Topics

### Properties

- ``s``
- ``oid``
- ``asn1``
- ``der``
- ``pem``
- ``description``

### Constructors

- ``init(kind:)``
- ``init(s:)``
- ``init(der:)``
- ``init(pem:)``

### Methods

- ``sign(message:context:deterministic:)``
