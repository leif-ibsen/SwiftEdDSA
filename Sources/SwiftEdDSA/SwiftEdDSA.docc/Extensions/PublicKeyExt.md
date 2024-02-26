# ``SwiftEdDSA/PublicKey``

The public key - either an Ed25519 public key or an Ed448 public key

## Topics

### Properties

- ``r``
- ``oid``
- ``asn1``
- ``der``
- ``pem``
- ``description``

### Constructors

- ``init(r:)``
- ``init(privateKey:)``
- ``init(der:)``
- ``init(pem:)``

### Methods

- ``verify(signature:message:context:)``

