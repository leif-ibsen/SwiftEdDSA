# Load Existing Keys

## 

### To load keys from their PEM encoding
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

let pub = try PublicKey(pem: pubPEM)
let priv = try PrivateKey(pem: privPEM)

print(pub)
print(priv)
```
giving:
```swift
Sequence (2):
    Sequence (1):
    Object Identifier: 1.3.101.112
    Bit String (256): 11100111 11010101 11010100 11111010 11100010 11000011 10011111 01110111 11010101 01001100 00110111 11001011 01100101 01110010 01100111 00100001 00111010 10011011 01100010 10000011 11110000 11000101 00101000 11011111 01010001 11101000 01100100 11110011 11110001 00111101 10110010 11010010

Sequence (3):
    Integer: 0
    Sequence (1):
       Object Identifier: 1.3.101.112
    Octet String (34): 04 20 76 4d f2 31 93 00 f4 d2 66 86 4e f4 f5 83 85 38 11 0e b3 b9 43 a7 16 d4 85 82 c5 cb 26 a1 9e d7
```
### To create a public key corresponding to a private key
```swift
let pubKey = PublicKey(privateKey: privKey)
```
