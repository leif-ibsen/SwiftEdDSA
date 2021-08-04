//
//  Ed.swift
//  SwiftEd
//
//  Created by Leif Ibsen on 24/04/2020.
//

import ASN1
import BigInt

///
/// An 8-bit unsigned integer
///
public typealias Byte = UInt8
///
/// An array of 8-bit unsigned integers
///
public typealias Bytes = [Byte]

///
/// The Ed class exists to provide a namespace, there is no Ed instances.
///
public class Ed {
        
    static let OID25519 = ASN1ObjectIdentifier("1.3.101.112")!
    static let OID448 = ASN1ObjectIdentifier("1.3.101.113")!
    
    // Not to be instantiated
    private init() {
    }
    

    // MARK: Exceptions

    ///
    /// Exceptions
    ///
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

    ///
    /// Curve kind - Ed25519 or Ed448
    ///
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
    /// - Returns: The PublicKey/PrivateKey pair
    public static func makeKeyPair(kind: Ed.Kind) -> (PublicKey, PrivateKey) {
        let privKey = PrivateKey(kind: kind)
        return (PublicKey(privateKey: privKey), privKey)
    }
    
    /// Checks a key pair for validity
    ///
    /// - Parameters:
    ///   - r: The public key value
    ///   - s: The private key value
    /// - Returns: *true* iff r/s is a valid key pair
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
