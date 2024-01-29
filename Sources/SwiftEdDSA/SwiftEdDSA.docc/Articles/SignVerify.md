# Sign and Verify

## 

### To sign a message and verify a signature
```swift
import SwiftEdDSA

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

// Sign deterministically
let deterministicSig = try privKey.sign(message: msg, deterministic: true)

// Sign non-deterministically
let nonDeterministicSig = try privKey.sign(message: msg, deterministic: false)

print("Verified:", pubKey.verify(signature: deterministicSig, message: msg))
print("Verified:", pubKey.verify(signature: nonDeterministicSig, message: msg))
```
giving:
```swift
Verified: true
Verified: true
```
