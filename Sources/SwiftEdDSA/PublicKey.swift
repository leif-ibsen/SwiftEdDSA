//
//  File.swift
//  
//
//  Created by Leif Ibsen on 08/09/2023.
//

import ASN1
import Digest

public class PublicKey: CustomStringConvertible {
    
    // MARK: Stored Properties

    /// The public key value - 32 bytes for Ed25519, 57 bytes for Ed448
    public let r: Bytes
    /// The curve OID
    public let oid: ASN1ObjectIdentifier
    
    var points25519: [Point25519]
    var points448: [Point448]

    
    // MARK: Computed Properties

    /// The ASN1 encoding of `self`
    public var asn1: ASN1 { get { do { return ASN1Sequence().add(ASN1Sequence().add(self.oid)).add(try ASN1BitString(self.r, 0)) } catch { return ASN1.NULL } } }
    /// The DER encoding of `self`
    public var der: Bytes { get { return self.asn1.encode() } }
    /// The PEM encoding of `self`
    public var pem: String { get { return Base64.pemEncode(self.asn1.encode(), "PUBLIC KEY") } }
    /// A textual representation of the ASN1 encoding of `self`
    public var description: String { get { return self.asn1.description } }

    
    // MARK: Constructors

    /// Creates a public key from its value
    ///
    /// - Parameters:
    ///   - r: The public key value, 32 bytes for Ed25519 - 57 bytes for Ed448
    /// - Throws: An exception if the key size is wrong or `r` cannot be decoded as a curve point
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
                let md = MessageDigest(.SHA2_512)
                md.update(privateKey.s)
                var h = Bytes(md.digest()[0 ..< 32])
                h[0] &= 0xf8
                h[31] &= 0x7f
                h[31] |= 0x40
                try self.init(r: Point25519.multiplyG(h).encode())
            } else {
                let shake = SHAKE(.SHAKE256)
                shake.update(privateKey.s)
                var h = shake.digest(57)
                h[0] &= 0xfc
                h[55] |= 0x80
                h[56] = 0x00
                try self.init(r: Point448.multiplyG(h).encode())
            }
        } catch {
            fatalError("PrivateKey inconsistency")
        }
    }

    /// Creates a public key from its DER encoding
    ///
    /// - Parameters:
    ///   - der: The public key DER encoding
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
    ///   - message: The message to verify signature for
    ///   - context: The context - must be the same as in the corresponding sign operation for the verification to succeed
    /// - Returns: `true` if the signature is verified, else `false`
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
            let md = MessageDigest(.SHA2_512)
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
            let shake = SHAKE(.SHAKE256)
            shake.update(Ed448.dom4Bytes(context))
            shake.update(R)
            shake.update(self.r)
            shake.update(message)
            let k = shake.digest(114)
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

