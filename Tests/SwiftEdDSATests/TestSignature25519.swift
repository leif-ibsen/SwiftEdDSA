//
//  TestSignature25519.swift
//  SwiftEdTests
//
//  Created by Leif Ibsen on 06/03/2020.
//

import XCTest
@testable import SwiftEdDSA
import Digest

class TestSignature25519: XCTestCase {

    // Test vectors from RFC 8032 section 7.1
    
    let secretKey1 = Base64.hex2bytes("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")!
    let publicKey1 = Base64.hex2bytes("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")!
    let message1 = Base64.hex2bytes("")!
    let signature1 = Base64.hex2bytes(
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")!

    let secretKey2 = Base64.hex2bytes("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")!
    let publicKey2 = Base64.hex2bytes("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c")!
    let message2 = Base64.hex2bytes("72")!
    let signature2 = Base64.hex2bytes(
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00")!

    let secretKey3 = Base64.hex2bytes("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7")!
    let publicKey3 = Base64.hex2bytes("fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025")!
    let message3 = Base64.hex2bytes("af82")!
    let signature3 = Base64.hex2bytes(
        "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a")!

    let secretKey4 = Base64.hex2bytes("833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42")!
    let publicKey4 = Base64.hex2bytes("ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf")!
    let message4 = Base64.hex2bytes(
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f")!
    let signature4 = Base64.hex2bytes(
        "dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b58909351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704")!

    func doTest1(_ secretKey: Bytes, _ publicKey: Bytes, _ message: Bytes, _ signature: Bytes) throws {
        let privKey = try PrivateKey(s: secretKey)
        let pubKey = PublicKey(privateKey: privKey)
        XCTAssertEqual(pubKey.r, publicKey)
        let sig = try privKey.sign(message: message, deterministic: true)
        XCTAssertEqual(sig, signature)
        XCTAssert(pubKey.verify(signature: sig, message: message))
    }

    func doTest2(_ secretKey: Bytes, _ publicKey: Bytes) throws {
        let privKey = try PrivateKey(s: secretKey)
        let pubKey1 = try PublicKey(r: publicKey)
        let pubKey = try PublicKey(r: pubKey1.r)
        XCTAssertTrue(Ed.keyPairIsValid(r: pubKey.r, s: privKey.s))
    }

    func test1() throws {
        try doTest1(secretKey1, publicKey1, message1, signature1)
        try doTest1(secretKey2, publicKey2, message2, signature2)
        try doTest1(secretKey3, publicKey3, message3, signature3)
        try doTest1(secretKey4, publicKey4, message4, signature4)
    }
    
    func test2() throws {
        try doTest2(secretKey1, publicKey1)
        try doTest2(secretKey2, publicKey2)
        try doTest2(secretKey3, publicKey3)
        try doTest2(secretKey4, publicKey4)
    }
    
    func test3() {
        XCTAssertTrue(Ed.keyPairIsValid(r: publicKey1, s: secretKey1))
        XCTAssertFalse(Ed.keyPairIsValid(r: publicKey1, s: secretKey2))
        XCTAssertFalse(Ed.keyPairIsValid(r: publicKey1, s: secretKey3))
        XCTAssertFalse(Ed.keyPairIsValid(r: publicKey1, s: secretKey4))
        XCTAssertTrue(Ed.keyPairIsValid(r: publicKey2, s: secretKey2))
        XCTAssertFalse(Ed.keyPairIsValid(r: publicKey2, s: secretKey1))
        XCTAssertFalse(Ed.keyPairIsValid(r: publicKey2, s: secretKey3))
        XCTAssertFalse(Ed.keyPairIsValid(r: publicKey2, s: secretKey4))
        XCTAssertTrue(Ed.keyPairIsValid(r: publicKey3, s: secretKey3))
        XCTAssertFalse(Ed.keyPairIsValid(r: publicKey3, s: secretKey1))
        XCTAssertFalse(Ed.keyPairIsValid(r: publicKey3, s: secretKey2))
        XCTAssertFalse(Ed.keyPairIsValid(r: publicKey3, s: secretKey4))
        XCTAssertTrue(Ed.keyPairIsValid(r: publicKey4, s: secretKey4))
        XCTAssertFalse(Ed.keyPairIsValid(r: publicKey4, s: secretKey1))
        XCTAssertFalse(Ed.keyPairIsValid(r: publicKey4, s: secretKey2))
        XCTAssertFalse(Ed.keyPairIsValid(r: publicKey4, s: secretKey3))
    }

    // Project Wycheproof test vectors
    
    let wpPublicKey = Base64.hex2bytes("7d4d0e7f6153a69b6242b522abbee685fda4420f8834b108c3bdae369ef549fa")!
    let wpSecretKey = Base64.hex2bytes("add4bb8103785baf9ac534258e8aaf65f5f1adb5ef5f3df19bb80ab989c4d64b")!
    let wpMessage1 = Base64.hex2bytes("")!
    let wpSignature1 = Base64.hex2bytes(
        "d4fbdb52bfa726b44d1786a8c0d171c3e62ca83c9e5bbe63de0bb2483f8fd6cc1429ab72cafc41ab56af02ff8fcc43b99bfe4c7ae940f60f38ebaa9d311c4007")!
    let wpMessage2 = Base64.hex2bytes("78")!
    let wpSignature2 = Base64.hex2bytes(
        "d80737358ede548acb173ef7e0399f83392fe8125b2ce877de7975d8b726ef5b1e76632280ee38afad12125ea44b961bf92f1178c9fa819d020869975bcbe109")!
    let wpMessage3 = Base64.hex2bytes("54657374")!
    let wpSignature3 = Base64.hex2bytes(
        "7c38e026f29e14aabd059a0f2db8b0cd783040609a8be684db12f82a27774ab07a9155711ecfaf7f99f277bad0c6ae7e39d4eef676573336a5c51eb6f946b30d")!
    let wpMessage4 = Base64.hex2bytes("48656c6c6f")!
    let wpSignature4 = Base64.hex2bytes(
        "1c1ad976cbaae3b31dee07971cf92c928ce2091a85f5899f5e11ecec90fc9f8e93df18c5037ec9b29c07195ad284e63d548cd0a6fe358cc775bd6c1608d2c905")!
    let wpMessage5 = Base64.hex2bytes("313233343030")!
    let wpSignature5 = Base64.hex2bytes(
        "657c1492402ab5ce03e2c3a7f0384d051b9cf3570f1207fc78c1bcc98c281c2bf0cf5b3a289976458a1be6277a5055545253b45b07dcc1abd96c8b989c00f301")!
    let wpMessage6 = Base64.hex2bytes("000000000000000000000000")!
    let wpSignature6 = Base64.hex2bytes(
        "d46543bfb892f84ec124dcdfc847034c19363bf3fc2fa89b1267833a14856e52e60736918783f950b6f1dd8d40dc343247cd43ce054c2d68ef974f7ed0f3c60f")!
    let wpMessage7 = Base64.hex2bytes(
        "6161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161")!
    let wpSignature7 = Base64.hex2bytes(
        "879350045543bc14ed2c08939b68c30d22251d83e018cacbaf0c9d7a48db577e80bdf76ce99e5926762bc13b7b3483260a5ef63d07e34b58eb9c14621ac92f00")!
    let wpMessage8 = Base64.hex2bytes(
        "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f60")!
    let wpSignature8 = Base64.hex2bytes(
        "7bdc3f9919a05f1d5db4a3ada896094f6871c1f37afc75db82ec3147d84d6f237b7e5ecc26b59cfea0c7eaf1052dc427b0f724615be9c3d3e01356c65b9b5109")!
    let wpMessage9 = Base64.hex2bytes("ffffffffffffffffffffffffffffffff")!
    let wpSignature9 = Base64.hex2bytes(
        "5dbd7360e55aa38e855d6ad48c34bd35b7871628508906861a7c4776765ed7d1e13d910faabd689ec8618b78295c8ab8f0e19c8b4b43eb8685778499e943ae04")!

    func test4() throws {
        try doTest1(wpSecretKey, wpPublicKey, wpMessage1, wpSignature1)
        try doTest1(wpSecretKey, wpPublicKey, wpMessage2, wpSignature2)
        try doTest1(wpSecretKey, wpPublicKey, wpMessage3, wpSignature3)
        try doTest1(wpSecretKey, wpPublicKey, wpMessage4, wpSignature4)
        try doTest1(wpSecretKey, wpPublicKey, wpMessage5, wpSignature5)
        try doTest1(wpSecretKey, wpPublicKey, wpMessage6, wpSignature6)
        try doTest1(wpSecretKey, wpPublicKey, wpMessage7, wpSignature7)
        try doTest1(wpSecretKey, wpPublicKey, wpMessage8, wpSignature8)
        try doTest1(wpSecretKey, wpPublicKey, wpMessage9, wpSignature9)
    }

    func doTest5(_ message: Bytes) throws {
        let privKey = try PrivateKey(s: wpSecretKey)
        let pubKey = try PublicKey(r: wpPublicKey)
        for _ in 0 ..< 5 {
            var sig = try privKey.sign(message: message, deterministic: false)
            XCTAssertTrue(sig[63] < 0x40)
            XCTAssertTrue(pubKey.verify(signature: sig, message: message))
            XCTAssertFalse(pubKey.verify(signature: sig, message: message + [1]))
            sig[0] &+= 1
            XCTAssertFalse(pubKey.verify(signature: sig, message: message))
        }
    }

    // Test non-deterministic signatures
    func test5() throws {
        try doTest5(wpMessage1)
        try doTest5(wpMessage2)
        try doTest5(wpMessage3)
        try doTest5(wpMessage4)
        try doTest5(wpMessage5)
        try doTest5(wpMessage6)
        try doTest5(wpMessage7)
        try doTest5(wpMessage8)
        try doTest5(wpMessage9)
    }

    // Test signature encode/decode
    func test6() throws {
        let (pub, priv) = Ed.makeKeyPair(kind: .ed25519)
        let sig1 = try priv.sign(message: [], deterministic: true)
        let sig2 = try priv.sign(message: [], deterministic: false)
        XCTAssertTrue(pub.verify(signature: sig1, message: []))
        XCTAssertTrue(pub.verify(signature: sig2, message: []))
        XCTAssertEqual(sig1, try Ed.decodeSignature(signature: Ed.encodeSignature(signature: sig1)))
        XCTAssertEqual(sig2, try Ed.decodeSignature(signature: Ed.encodeSignature(signature: sig2)))
    }

    func test7() throws {
        let (pubKey25519, privKey25519) = Ed.makeKeyPair(kind: .ed25519)
        let sig1 = try privKey25519.sign(message: [], context: [])
        XCTAssertTrue(pubKey25519.verify(signature: sig1, message: [], context: []))
        XCTAssertFalse(pubKey25519.verifyCT(signature: sig1, message: [], context: []))
        XCTAssertFalse(pubKey25519.verifyPH(signature: sig1, message: [], context: []))

        let sig2 = try privKey25519.signCT(message: [], context: [])
        XCTAssertFalse(pubKey25519.verify(signature: sig2, message: [], context: []))
        XCTAssertTrue(pubKey25519.verifyCT(signature: sig2, message: [], context: []))
        XCTAssertFalse(pubKey25519.verifyPH(signature: sig2, message: [], context: []))

        let sig3 = try privKey25519.signPH(message: [], context: [])
        XCTAssertFalse(pubKey25519.verify(signature: sig3, message: [], context: []))
        XCTAssertFalse(pubKey25519.verifyCT(signature: sig3, message: [], context: []))
        XCTAssertTrue(pubKey25519.verifyPH(signature: sig3, message: [], context: []))
    }

}
