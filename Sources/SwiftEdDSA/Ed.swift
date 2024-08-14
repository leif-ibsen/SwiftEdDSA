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
        /// Key size exception
        case keySize
        /// PEM structure exception
        case pemStructure
        /// Signature size exception
        case signatureSize
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

    /// Encode a signature to ASN1
    ///
    /// - Parameters:
    ///   - signature: The signature bytes
    /// - Returns: The ASN1 DER encoding of `signature`
    /// - Throws: An exception if the signature size is wrong
    public static func encodeSignature(signature: Bytes) throws -> ASN1 {
        if signature.count == 64 {
            return ASN1Sequence().add(ASN1OctetString(Bytes(signature[0 ..< 32]))).add(ASN1OctetString(Bytes(signature[32 ..< 64])))
        } else if signature.count == 114 {
            return ASN1Sequence().add(ASN1OctetString(Bytes(signature[0 ..< 57]))).add(ASN1OctetString(Bytes(signature[57 ..< 114])))
        } else {
            throw Ed.Ex.signatureSize
        }
    }

    /// Decode a signature ASN1 representation to bytes
    ///
    /// - Parameters:
    ///   - signature: The signature ASN1 DER representation
    /// - Returns: The signature bytes
    /// - Throws: An exception if the ASN1 structure is wrong
    public static func decodeSignature(signature: ASN1) throws -> Bytes {
        guard let seq = signature as? ASN1Sequence else {
            throw Ed.Ex.asn1Structure
        }
        let rs = seq.getValue()
        guard rs.count == 2 else {
            throw Ed.Ex.asn1Structure
        }
        guard let r = rs[0] as? ASN1OctetString else {
            throw Ed.Ex.asn1Structure
        }
        guard let s = rs[1] as? ASN1OctetString else {
            throw Ed.Ex.asn1Structure
        }
        if (r.value.count == 32 && s.value.count == 32) || (r.value.count == 57 && s.value.count == 57) {
            return r.value + s.value
        } else {
            throw Ed.Ex.asn1Structure
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
