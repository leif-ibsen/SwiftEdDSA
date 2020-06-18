//
//  TestPEM.swift
//  SwiftEdTests
//
//  Created by Leif Ibsen on 05/05/2020.
//

import XCTest

class TestPEM: XCTestCase {

    func doTest(kind: Ed.Kind) throws {
        let (pub, priv) = Ed.makeKeyPair(kind: kind)
        XCTAssertTrue(Ed.keyPairIsValid(r: pub.r, s: priv.s))
        let pub1 = try PublicKey(pem: pub.pem)
        let priv1 = try PrivateKey(pem: priv.pem)
        XCTAssertEqual(pub.r, pub1.r)
        XCTAssertEqual(pub.oid, pub1.oid)
        XCTAssertEqual(priv.s, priv1.s)
        XCTAssertEqual(priv.oid, priv1.oid)
        let pub2 = try PublicKey(der: pub.asn1.encode())
        let priv2 = try PrivateKey(der: priv.asn1.encode())
        XCTAssertEqual(pub.r, pub2.r)
        XCTAssertEqual(pub.oid, pub2.oid)
        XCTAssertEqual(priv.s, priv2.s)
        XCTAssertEqual(priv.oid, priv2.oid)
    }

    func test25519() throws {
        try doTest(kind: .ed25519)
    }

    func test448() throws {
        try doTest(kind: .ed448)
    }

}
