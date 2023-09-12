//
//  TestDER.swift
//  
//
//  Created by Leif Ibsen on 11/09/2023.
//

import XCTest
@testable import SwiftEdDSA

final class TestDER: XCTestCase {

    func doTest(_ kind: Ed.Kind) throws {
        let (pub1, priv1) = Ed.makeKeyPair(kind: kind)
        let pubDER1 = pub1.der
        let privDER1 = priv1.der
        let pub2 = try PublicKey(der: pubDER1)
        let priv2 = try PrivateKey(der: privDER1)
        XCTAssertEqual(pub1.r, pub2.r)
        XCTAssertEqual(pub1.oid, pub2.oid)
        XCTAssertEqual(priv1.s, priv2.s)
        XCTAssertEqual(priv1.oid, priv2.oid)
    }

    func test25519() throws {
        try doTest(.ed25519)
    }

    func test448() throws {
        try doTest(.ed448)
    }

}
