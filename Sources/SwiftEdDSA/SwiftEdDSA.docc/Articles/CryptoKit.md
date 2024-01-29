# Apple CryptoKit Compatibility

## 
SwiftEdDSA keys of kind `.ed25519` corresponds to Apple CryptoKit `Curve25519` keys.
Keys of kind `.ed448` is not supported in Apple CryptoKit.

Signatures generated by Apple CryptoKit can be verified by SwiftEdDSA and 
signatures of kind `.ed25519` generated by SwiftEdDSA can be verified by Apple CryptoKit.

To convert SwiftEdDSA keys - say `edPriv` and `edPub` - to corresponding CryptoKit keys:
```swift
let ckPriv = try CryptoKit.Curve25519.Signing.PrivateKey(rawRepresentation: edPriv.s)
let ckPub = try CryptoKit.Curve25519.Signing.PublicKey(rawRepresentation: edPub.r)
```
To convert CryptoKit keys - say `ckPriv` and `ckPub` - to corresponding SwiftEdDSA keys:
```swift
let edPriv = try PrivateKey(s: Bytes(ckPriv.rawRepresentation))
let edPub = try PublicKey(r: Bytes(ckPub.rawRepresentation))
```