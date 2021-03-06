//
//  Key.swift
//  SwiftEd
//
//  Created by Leif Ibsen on 24/04/2020.
//

import Foundation
import ASN1
import BigInt

///
/// A public key - either an Ed25519 public key or an Ed448 public key
///
public class PublicKey: CustomStringConvertible {
    
    // MARK: Stored Properties

    /// The public key value - 32 bytes for Ed25519, 57 bytes for Ed448
    public let r: Bytes
    /// The curve OID
    public let oid: ASN1ObjectIdentifier
    
    var points25519: [Point25519]
    var points448: [Point448]

    
    // MARK: Computed Properties

    /// The ASN1 encoding of *self*
    public var asn1: ASN1 { get { return ASN1Sequence().add(ASN1Sequence().add(self.oid)).add(ASN1BitString(self.r, 0)) } }
    /// A textual representation of the ASN1 encoding of *self*
    public var description: String { get { return self.asn1.description } }
    /// The PEM encoding of *self*
    public var pem: String { get { return Base64.pemEncode(self.asn1.encode(), "PUBLIC KEY") } }
    
    
    // MARK: Constructors

    /// Creates a public key from its value
    ///
    /// - Parameters:
    ///   - r: The public key value, 32 bytes for Ed25519 - 57 bytes for Ed448
    /// - Throws: An exception if the key size is wrong or *r* cannot be decoded to a curve point
    public init(r: Bytes) throws {
        self.r = r
        if r.count == 32 {
            self.oid = Ed.OID25519
            self.points25519 = [Point25519](repeating: Point25519.INFINITY, count: 128)
            self.points25519[0] = try Ed25519.decode(self.r)
            for i in 1 ..< 128 {
                self.points25519[i] = self.points25519[i - 1].double(4)
            }
            self.points448 = []
        } else if r.count == 57 {
            self.oid = Ed.OID448
            self.points448 = [Point448](repeating: Point448.INFINITY, count: 228)
            self.points448[0] = try Ed448.decode(self.r)
            for i in 1 ..< 228 {
                self.points448[i] = self.points448[i - 1].double(4)
            }
            self.points25519 = []
        } else {
            throw Ed.Ex.keySize
        }
    }
    
    /// Creates a public key corresponding to a private key
    ///
    /// - Parameters:
    ///   - privateKey: The private key
    public convenience init(privateKey: PrivateKey) {
        do {
            if privateKey.oid == Ed.OID25519 {
                let md = MD()
                md.update(privateKey.s)
                let (h, _) = md.digest2()
                try self.init(r: Point25519.multiplyG(h).encode())
            } else {
                let shake = SHAKE256()
                shake.update(privateKey.s)
                let (h, _) = shake.digest2()
                try self.init(r: Point448.multiplyG(h).encode())
            }
        } catch {
            fatalError("PrivateKey inconsistency")
        }
    }

    /// Creates a public key from its ASN1 DER encoding
    ///
    /// - Parameters:
    ///   - der: The public key ASN1 DER encoding
    /// - Throws: An exception if the DER encoding is wrong
    public convenience init(der: Bytes) throws {
        let asn1 = try ASN1.build(der)
        guard let seq = asn1 as? ASN1Sequence else {
            throw Ed.Ex.asn1Structure
        }
        if seq.getValue().count < 2 {
            throw Ed.Ex.asn1Structure
        }
        guard let seq1 = seq.get(0) as? ASN1Sequence else {
            throw Ed.Ex.asn1Structure
        }
        guard let bits = seq.get(1) as? ASN1BitString else {
            throw Ed.Ex.asn1Structure
        }
        if seq1.getValue().count < 1 {
            throw Ed.Ex.asn1Structure
        }
        guard let oid = seq1.get(0) as? ASN1ObjectIdentifier else {
            throw Ed.Ex.asn1Structure
        }
        if oid == Ed.OID25519 && bits.bits.count == 32 && bits.unused == 0 {
            try self.init(r: bits.bits)
        }
        else if oid == Ed.OID448 && bits.bits.count == 57 && bits.unused == 0 {
            try self.init(r: bits.bits)
        } else {
            throw Ed.Ex.asn1Structure
        }
    }
    
    /// Creates a public key from its PEM encoding
    ///
    /// - Parameters:
    ///   - pem: The public key PEM encoding
    /// - Throws: An exception if the PEM encoding is wrong
    public convenience init(pem: String) throws {
        try self.init(der: Base64.pemDecode(pem, "PUBLIC KEY"))
    }


    // MARK: Instance Methods

    /// Verifies an EdDSA signature
    ///
    /// - Parameters:
    ///   - signature: The EdDSA signature to verify
    ///   - message: The message to verify *signature* for
    ///   - context: The context - must be the same as in the corresponding sign operation for the verification to succeed
    /// - Returns: *true* iff the signature is verified
    public func verify(signature: Bytes, message: Bytes, context: Bytes = []) -> Bool {
        if signature.count == 64 {
            if context.count > 0 {
                return false
            }
            let R = Bytes(signature[0 ..< 32])
            let S = Bytes(signature[32 ..< 64])
            if Ed.toBInt(S) >= Ed25519.L {
                return false
            }
            let md = MD()
            md.update(R)
            md.update(self.r)
            md.update(message)
            let k = md.digest()
            let p = Point25519.multiplyG(S).add(self.multiply25519(k).negate())
            return p.encode() == R
        } else if signature.count == 114 {
            if context.count > 255 {
                return false
            }
            let R = Bytes(signature[0 ..< 57])
            let S = Bytes(signature[57 ..< 114])
            if Ed.toBInt(S) >= Ed448.L {
                return false
            }
            let shake = SHAKE256()
            shake.update(Ed448.dom4Bytes(context))
            shake.update(R)
            shake.update(self.r)
            shake.update(message)
            let k = shake.digest()
            let p = Point448.multiplyG(S).add(self.multiply448(k).negate())
            return p.encode() == R
        }
        return false
    }
    
    // Multiply the public key point
    // [GUIDE] - algorithm 3.41, window width = 4
    func multiply25519(_ n: Bytes) -> Point25519 {
        var a = Point25519.INFINITY
        var b = Point25519.INFINITY
        for j in (1 ..< 16).reversed() {
            var k = 0
            for i in 0 ..< n.count {
                if n[i] & 0x0f == j {
                    b = b.add(self.points25519[k])
                }
                if (n[i] >> 4) & 0x0f == j {
                    b = b.add(self.points25519[k + 1])
                }
                k += 2
            }
            a = a.add(b)
        }
        return a
    
    }
    
    func multiply448(_ n: Bytes) -> Point448 {
        var a = Point448.INFINITY
        var b = Point448.INFINITY
        for j in (1 ..< 16).reversed() {
            var k = 0
            for i in 0 ..< n.count {
                if n[i] & 0x0f == j {
                    b = b.add(self.points448[k])
                }
                if (n[i] >> 4) & 0x0f == j {
                    b = b.add(self.points448[k + 1])
                }
                k += 2
            }
            a = a.add(b)
        }
        return a
    }

}

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
    /// A textual representation of the ASN1 encoding of *self*
    public var description: String { get { return self.asn1.description } }
    /// The PEM encoding of *self*
    public var pem: String { get { return Base64.pemEncode(self.asn1.encode(), "PRIVATE KEY") } }

    
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

    /// Creates a private key from its ASN1 DER encoding
    ///
    /// - Parameters:
    ///   - der: The private key ASN1 DER encoding
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
