//
//  TestSignature25519.swift
//  SwiftEdTests
//
//  Created by Leif Ibsen on 06/03/2020.
//

import XCTest
@testable import SwiftEdDSA
import Digest

class TestSignatureCT: XCTestCase {

    // Test vectors from RFC 8032 section 7.2
    
    let secretKey1 = Base64.hex2bytes("0305334e381af78f141cb666f6199f57bc3495335a256a95bd2a55bf546663f6")!
    let publicKey1 = Base64.hex2bytes("dfc9425e4f968f7f0c29f0259cf5f9aed6851c2bb4ad8bfb860cfee0ab248292")!
    let message1 = Base64.hex2bytes("f726936d19c800494e3fdaff20b276a8")!
    let context1 = Base64.hex2bytes("666f6f")!
    let signature1 = Base64.hex2bytes(
        "55a4cc2f70a54e04288c5f4cd1e45a7bb520b36292911876cada7323198dd87a8b36950b95130022907a7fb7c4e9b2d5f6cca685a587b4b21f4b888e4e7edb0d")!

    let secretKey2 = Base64.hex2bytes("0305334e381af78f141cb666f6199f57bc3495335a256a95bd2a55bf546663f6")!
    let publicKey2 = Base64.hex2bytes("dfc9425e4f968f7f0c29f0259cf5f9aed6851c2bb4ad8bfb860cfee0ab248292")!
    let message2 = Base64.hex2bytes("f726936d19c800494e3fdaff20b276a8")!
    let context2 = Base64.hex2bytes("626172")!
    let signature2 = Base64.hex2bytes(
        "fc60d5872fc46b3aa69f8b5b4351d5808f92bcc044606db097abab6dbcb1aee3216c48e8b3b66431b5b186d1d28f8ee15a5ca2df6668346291c2043d4eb3e90d")!

    let secretKey3 = Base64.hex2bytes("0305334e381af78f141cb666f6199f57bc3495335a256a95bd2a55bf546663f6")!
    let publicKey3 = Base64.hex2bytes("dfc9425e4f968f7f0c29f0259cf5f9aed6851c2bb4ad8bfb860cfee0ab248292")!
    let message3 = Base64.hex2bytes("508e9e6882b979fea900f62adceaca35")!
    let context3 = Base64.hex2bytes("666f6f")!
    let signature3 = Base64.hex2bytes(
        "8b70c1cc8310e1de20ac53ce28ae6e7207f33c3295e03bb5c0732a1d20dc64908922a8b052cf99b7c4fe107a5abb5b2c4085ae75890d02df26269d8945f84b0b")!

    let secretKey4 = Base64.hex2bytes("ab9c2853ce297ddab85c993b3ae14bcad39b2c682beabc27d6d4eb20711d6560")!
    let publicKey4 = Base64.hex2bytes("0f1d1274943b91415889152e893d80e93275a1fc0b65fd71b4b0dda10ad7d772")!
    let message4 = Base64.hex2bytes("f726936d19c800494e3fdaff20b276a8")!
    let context4 = Base64.hex2bytes("666f6f")!
    let signature4 = Base64.hex2bytes(
        "21655b5f1aa965996b3f97b3c849eafba922a0a62992f73b3d1b73106a84ad85e9b86a7b6005ea868337ff2d20a7f5fbd4cd10b0be49a68da2b2e0dc0ad8960f")!

    func doTest1(_ secretKey: Bytes, _ publicKey: Bytes, _ msg: Bytes, _ ctx: Bytes, _ sig: Bytes) throws {
        let privKey = try PrivateKey(s: secretKey)
        let sigx = try privKey.signCT(message: msg, context: ctx)
        let pubKey = try PublicKey(r: publicKey)
        XCTAssertEqual(sig, sigx)
        XCTAssertTrue(pubKey.verifyCT(signature: sig, message: msg, context: ctx))
    }

    func test1() throws {
        try doTest1(secretKey1, publicKey1, message1, context1, signature1)
        try doTest1(secretKey2, publicKey2, message2, context2, signature2)
        try doTest1(secretKey3, publicKey3, message3, context3, signature3)
        try doTest1(secretKey4, publicKey4, message4, context4, signature4)
    }

    func test2() throws {
        let (pubKey, privKey) = Ed.makeKeyPair(kind: .ed25519)
        let sig = try privKey.signCT(message: [], context: [])
        XCTAssertTrue(pubKey.verifyCT(signature: sig, message: [], context: []))
    }

}
