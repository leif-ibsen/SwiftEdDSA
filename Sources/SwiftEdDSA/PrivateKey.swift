//
//  File.swift
//  
//
//  Created by Leif Ibsen on 08/09/2023.
//

import Foundation
import BigInt
import ASN1

///
/// A private key - either an Ed25519 private key or an Ed448 private key
///
public class PrivateKey: CustomStringConvertible {

    // MARK: Stored Properties
    
    /// The private key value - 32 bytes for Ed25519, 57 bytes for Ed448
    public let s: Bytes
    /// The curve OID
    public let oid: ASN1ObjectIdentifier


    // MARK: Computed Properties

    /// The ASN1 encoding of *self*
    public var asn1: ASN1 { get { return ASN1Sequence().add(ASN1Integer(BInt.ZERO)).add(ASN1Sequence().add(self.oid)).add(ASN1OctetString([4, Byte(self.s.count)] + self.s)) } }
    /// The DER encoding of *self*
    public var der: Bytes { get { return self.asn1.encode() } }
    /// The PEM encoding of *self*
    public var pem: String { get { return Base64.pemEncode(self.asn1.encode(), "PRIVATE KEY") } }
    /// A textual representation of the ASN1 encoding of *self*
    public var description: String { get { return self.asn1.description } }

    
    // MARK: Constructors

    /// Creates a new private key of the specified kind
    ///
    /// - Parameters:
    ///   - kind: The private key kind - Ed25519 or Ed448
    public init(kind: Ed.Kind) {
        var n: Int
        switch kind {
        case .ed25519:
            n = 32
            self.oid = Ed.OID25519
        case .ed448:
            n = 57
            self.oid = Ed.OID448
        }
        var x = Bytes(repeating: 0, count: n)
        let ok = SecRandomCopyBytes(kSecRandomDefault, n, &x)
        assert(ok == errSecSuccess, "Random bytes")
        self.s = x
    }

    /// Creates a private key from its value
    ///
    /// - Parameters:
    ///   - s: The private key value, 32 bytes for Ed25519 - 57 bytes for Ed448
    /// - Throws: An exception if the key size is wrong
    public init(s: Bytes) throws {
        self.s = s
        if s.count == 32 {
            self.oid = Ed.OID25519
        } else if s.count == 57 {
            self.oid = Ed.OID448
        } else {
            throw Ed.Ex.keySize
        }
    }

    /// Creates a private key from its DER encoding
    ///
    /// - Parameters:
    ///   - der: The private key DER encoding
    /// - Throws: An exception if the DER encoding is wrong
    public convenience init(der: Bytes) throws {
        let asn1 = try ASN1.build(der)
        guard let seq = asn1 as? ASN1Sequence else {
            throw Ed.Ex.asn1Structure
        }
        if seq.getValue().count < 3 {
            throw Ed.Ex.asn1Structure
        }
        guard let int = seq.get(0) as? ASN1Integer else {
            throw Ed.Ex.asn1Structure
        }
        if int != ASN1.ZERO {
            throw Ed.Ex.asn1Structure
        }
        guard let seq1 = seq.get(1) as? ASN1Sequence else {
            throw Ed.Ex.asn1Structure
        }
        guard let octets = seq.get(2) as? ASN1OctetString else {
            throw Ed.Ex.asn1Structure
        }
        if seq1.getValue().count < 1 {
            throw Ed.Ex.asn1Structure
        }
        guard let oid = seq1.get(0) as? ASN1ObjectIdentifier else {
            throw Ed.Ex.asn1Structure
        }
        if oid == Ed.OID25519 && octets.value.count == 34 {
            try self.init(s: Bytes(octets.value[2 ..< 34]))
        }
        else if oid == Ed.OID448 && octets.value.count == 59 {
            try self.init(s: Bytes(octets.value[2 ..< 59]))
        } else {
            throw Ed.Ex.asn1Structure
        }
    }

    /// Creates a private key from its PEM encoding
    ///
    /// - Parameters:
    ///   - pem: The private key PEM encoding
    /// - Throws: An exception if the PEM encoding is wrong
    public convenience init(pem: String) throws {
        try self.init(der: Base64.pemDecode(pem, "PRIVATE KEY"))
    }

    // MARK: Instance Methods

    /// Signs a message
    ///
    /// - Parameters:
    ///   - message: The message to sign
    ///   - context: The context - the default value is an empty array
    /// - Returns: The EdDSA signature - 64 bytes for Ed25519, 114 bytes for Ed448
    /// - Throws: A *context* exception if *context* contains more than 0 bytes for Ed25519 or more than 255 bytes for Ed448
    public func sign(message: Bytes, context: Bytes = []) throws -> Bytes {
        if self.oid == Ed.OID25519 {
            if context.count > 0 {
                throw Ed.Ex.context
            }
            let md = MD()
            md.update(self.s)
            let (h0, h1) = md.digest2()
            md.update(h1)
            md.update(message)
            let r = Ed25519.reduceModL(Ed.toBInt(md.digest()))
            let R = Point25519.multiplyG(Ed25519.toBytes(r)).encode()
            let a = Ed.toBInt(h0)
            let A = Point25519.multiplyG(h0).encode()
            md.update(R)
            md.update(A)
            md.update(message)
            let k = Ed25519.reduceModL(Ed.toBInt(md.digest()))
            return R + Ed25519.toBytes(Ed25519.reduceModL(k * a + r))
        } else {
            if context.count > 255 {
                throw Ed.Ex.context
            }
            let shake = SHAKE256()
            shake.update(self.s)
            let (h0, h1) = shake.digest2()
            shake.update(Ed448.dom4Bytes(context))
            shake.update(h1)
            shake.update(message)
            let r = Ed448.reduceModL(Ed.toBInt(shake.digest()))
            let R = Point448.multiplyG(Ed448.toBytes(r)).encode()
            let a = Ed.toBInt(h0)
            let A = Point448.multiplyG(h0).encode()
            shake.update(Ed448.dom4Bytes(context))
            shake.update(R)
            shake.update(A)
            shake.update(message)
            let k = Ed448.reduceModL(Ed.toBInt(shake.digest()))
            return R + Ed448.toBytes(Ed448.reduceModL(k * a + r))
        }
    }

}
