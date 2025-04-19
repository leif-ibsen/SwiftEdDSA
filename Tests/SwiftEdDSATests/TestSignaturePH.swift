//
//  TestSignature25519.swift
//  SwiftEdTests
//
//  Created by Leif Ibsen on 06/03/2020.
//

import XCTest
@testable import SwiftEdDSA
import Digest

class TestSignaturePH: XCTestCase {

    // Test vectors from RFC 8032 section 7.3 and section 7.5
    
    let secretKey1 = Base64.hex2bytes("833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42")!
    let publicKey1 = Base64.hex2bytes("ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf")!
    let message1 = Base64.hex2bytes("616263")!
    let context1 = Base64.hex2bytes("")!
    let signature1 = Base64.hex2bytes(
        "98a70222f0b8121aa9d30f813d683f809e462b469c7ff87639499bb94e6dae4131f85042463c2a355a2003d062adf5aaa10b8c61e636062aaad11c2a26083406")!

    let secretKey2 = Base64.hex2bytes(
        "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42ef7822e0d5104127dc05d6dbefde69e3ab2cec7c867c6e2c49")!
    let publicKey2 = Base64.hex2bytes(
        "259b71c19f83ef77a7abd26524cbdb3161b590a48f7d17de3ee0ba9c52beb743c09428a131d6b1b57303d90d8132c276d5ed3d5d01c0f53880")!
    let message2 = Base64.hex2bytes("616263")!
    let context2 = Base64.hex2bytes("")!
    let signature2 = Base64.hex2bytes(
        "822f6901f7480f3d5f562c592994d9693602875614483256505600bbc281ae381f54d6bce2ea911574932f52a4e6cadd78769375ec3ffd1b801a0d9b3f4030cd433964b6457ea39476511214f97469b57dd32dbc560a9a94d00bff07620464a3ad203df7dc7ce360c3cd3696d9d9fab90f00")!

    let secretKey3 = Base64.hex2bytes(
        "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42ef7822e0d5104127dc05d6dbefde69e3ab2cec7c867c6e2c49")!
    let publicKey3 = Base64.hex2bytes(
        "259b71c19f83ef77a7abd26524cbdb3161b590a48f7d17de3ee0ba9c52beb743c09428a131d6b1b57303d90d8132c276d5ed3d5d01c0f53880")!
    let message3 = Base64.hex2bytes("616263")!
    let context3 = Base64.hex2bytes("666f6f")!
    let signature3 = Base64.hex2bytes(
        "c32299d46ec8ff02b54540982814dce9a05812f81962b649d528095916a2aa481065b1580423ef927ecf0af5888f90da0f6a9a85ad5dc3f280d91224ba9911a3653d00e484e2ce232521481c8658df304bb7745a73514cdb9bf3e15784ab71284f8d0704a608c54a6b62d97beb511d132100")!

    func doTest1(_ secretKey: Bytes, _ publicKey: Bytes, _ message: Bytes, _ context: Bytes, _ signature: Bytes) throws {
        let privKey = try PrivateKey(s: secretKey)
        let pubKey = PublicKey(privateKey: privKey)
        XCTAssertEqual(pubKey.r, publicKey)
        var sig = try privKey.signPH(message: message, context: context, deterministic: true)
        XCTAssertEqual(sig, signature)
        XCTAssertTrue(pubKey.verifyPH(signature: sig, message: message, context: context))
        var msg = message
        msg[0] &+= 1
        XCTAssertFalse(pubKey.verifyPH(signature: sig, message: msg, context: context))
        sig[0] &+= 1
        XCTAssertFalse(pubKey.verifyPH(signature: sig, message: message, context: context))
    }

    func test1() throws {
        try doTest1(secretKey1, publicKey1, message1, context1, signature1)
        try doTest1(secretKey2, publicKey2, message2, context2, signature2)
        try doTest1(secretKey3, publicKey3, message3, context3, signature3)
    }
    

}
