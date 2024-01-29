# Create New Keys

## 

### To create a new private key
```swift
// Curve Ed25519
let privKey = PrivateKey(kind: .ed25519)

// Curve Ed448
let privKey = PrivateKey(kind: .ed448)
```
### To create a new key pair
```swift
// Curve Ed25519 key pair
let (pubKey, privKey) = Ed.makeKeyPair(kind: .ed25519)

// Curve Ed448 key pair
let (pubKey, privKey) = Ed.makeKeyPair(kind: .ed448)
```
