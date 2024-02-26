//
//  Ed.swift
//  SwiftEd
//
//  Created by Leif Ibsen on 24/04/2020.
//

import Foundation
import ASN1
import BigInt

/// Unsigned 8 bit value
public typealias Byte = UInt8

/// Array of unsigned 8 bit values
public typealias Bytes = [UInt8]

public class Ed {
        
    static let OID25519 = ASN1ObjectIdentifier("1.3.101.112")!
    static let OID448 = ASN1ObjectIdentifier("1.3.101.113")!
    
    // Not to be instantiated
    private init() {
    }
    
    static func randomBytes(_ bytes: inout Bytes) {
        guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess else {
            fatalError("randomBytes failed")
        }
    }

    // MARK: Exceptions

    /// The EdDSA exceptions
    public enum Ex: Error {
        /// ASN1 structure exception
        case asn1Structure
        /// Base64 exception
        case base64
        /// Context exception
        case context
        /// Point decoding exception
        case decode
        /// Keysize exception
        case keySize
        /// PEM structure exception
        case pemStructure
    }

    
    // MARK: Curve kinds

    /// The EdDSA curve kinds
    public enum Kind {
        /// Curve Ed25519
        case ed25519
        /// Curve Ed448
        case ed448
    }


    // MARK: Static Methods

    /// Creates a new key pair of the specified kind
    ///
    /// - Parameters:
    ///   - kind: The curve kind
    /// - Returns: The PublicKey / PrivateKey pair
    public static func makeKeyPair(kind: Ed.Kind) -> (PublicKey, PrivateKey) {
        let privKey = PrivateKey(kind: kind)
        return (PublicKey(privateKey: privKey), privKey)
    }
    
    /// Checks a key pair for validity
    ///
    /// - Parameters:
    ///   - r: The public key value
    ///   - s: The private key value
    /// - Returns: `true` if `r` and `s` constitute a valid key pair, else `false`
    public static func keyPairIsValid(r: Bytes, s: Bytes) -> Bool {
        do {
            return try PublicKey(privateKey: PrivateKey(s: s)).r == r
        } catch {
            return false
        }
    }

    static func toBInt(_ x: Bytes) -> BInt {
        var m = Limbs(repeating: 0, count: (x.count + 7) / 8)
        var j = -1
        for i in 0 ..< x.count {
            if i & 0x07 == 0 {
                j += 1
            }
            m[j] |= Limb(x[i]) << ((i & 0x07) * 8)
        }
        return BInt(m)
    }

}
