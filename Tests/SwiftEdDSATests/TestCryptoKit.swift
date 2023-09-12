//
//  TestCryptoKit.swift
//  
//
//  Created by Leif Ibsen on 08/09/2023.
//

import XCTest
@testable import SwiftEdDSA
import CryptoKit

final class TestCryptoKit: XCTestCase {

    let msg = Bytes(repeating: 7, count: 100)
    
    func test1() throws {
        
        // CryptoKit signs, SwiftEdDSA verifies
        
        let ckPriv = CryptoKit.Curve25519.Signing.PrivateKey()
        let edPub = try PublicKey(r: Bytes(ckPriv.publicKey.rawRepresentation))
            
        // CryptoKit signatures are not deterministic, so generate a few
        for _ in 0 ..< 5 {
            let sig = try ckPriv.signature(for: msg)
            XCTAssertTrue(edPub.verify(signature: Bytes(sig), message: msg))
        }
    }

    func test2() throws {

        // SwiftEdDSA signs, CryptoKit verifies

        let edPriv = PrivateKey(kind: .ed25519)
        let sig = try edPriv.sign(message: msg)
        let ckPub = try CryptoKit.Curve25519.Signing.PublicKey(rawRepresentation: PublicKey(privateKey: edPriv).r)
        XCTAssertTrue(ckPub.isValidSignature(sig, for: msg))
    }

}
