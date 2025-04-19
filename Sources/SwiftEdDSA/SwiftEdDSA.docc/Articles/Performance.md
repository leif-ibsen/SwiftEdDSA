# Performance

Execution times for certain SwiftEdDSA operations

## 
The time it takes to generate a new private key and to generate a public key from its private key
was measured on a MacBook Pro 2024, Apple M3 chip.

The signature generation and verification time for a short message was also measured. 
The results are shown below - units are milliseconds or microseconds.

| Operation            | Ed25519   | Ed448     |
|:---------------------|----------:|----------:|
| Generate private Key | 0.4 uSec  | 0.3 uSec  |
| Generate public Key  | 2.8 mSec  | 5.8 mSec  |
| Sign                 | 0.8 mSec  | 1.9 mSec  |
| Verify               | 1.0 mSec  | 2.5 mSec  |

> Note:
The public key constructor computes and caches information that subsequently speed-up signature verification.
>
> If the same public key is to be used for many signature verifications, it is more efficient to use the same key instance for all verifications,
rather than generate a new instance for each verification.

