# About EdDSA variants

## Overview

[RFC 8032] defines three EdDSA operation variants:

* The pure operation mode
* The contextualized operation mode
* The pre-hash operation mode

Ed25519 comes with all three variants.

Ed448 comes only with pure operation mode and pre-hash operation mode.

### Ed25519

For the pure operation mode, use the ``SwiftEdDSA/PrivateKey/sign(message:context:deterministic:)`` and ``SwiftEdDSA/PublicKey/verify(signature:message:context:)`` methods

For the contextualized operation mode, use the ``SwiftEdDSA/PrivateKey/signCT(message:context:deterministic:)`` and ``SwiftEdDSA/PublicKey/verifyCT(signature:message:context:)`` methods

For the pre-hash operation mode, use the ``SwiftEdDSA/PrivateKey/signPH(message:context:deterministic:)`` and ``SwiftEdDSA/PublicKey/verifyPH(signature:message:context:)`` methods

### Ed448

For the pure operation mode, use the ``SwiftEdDSA/PrivateKey/sign(message:context:deterministic:)`` and ``SwiftEdDSA/PublicKey/verify(signature:message:context:)`` methods

For the pre-hash operation mode, use the ``SwiftEdDSA/PrivateKey/signPH(message:context:deterministic:)`` and ``SwiftEdDSA/PublicKey/verifyPH(signature:message:context:)`` methods
