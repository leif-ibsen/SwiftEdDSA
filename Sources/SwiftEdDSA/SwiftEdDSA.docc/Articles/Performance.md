# Performance

## 
The signature generation and verification time for a short message and the time it takes to
generate a new private key and to generate a public key from its private key
was measured on an iMac 2021, Apple M1 chip. The results are shown below:

| Operation | Ed25519 | Ed448 |
|:----------|--------:|------:|
| Sign | 0.8 mSec | 2.1 mSec |
| Verify | 1.1 mSec | 3.0 mSec |
| Public Key Generation  | 2.8 mSec  | 6.6 mSec |
| Private Key Generation  | 0.67 uSec  | 0.61 uSec |

> Note:
The public key constructor computes and caches information that subsequently speed-up signature verification.
>
> If the same public key is to be used for many signature verifications, it is more efficient to use the same key instance for all verifications,
rather than generate a new instance for each verification.

