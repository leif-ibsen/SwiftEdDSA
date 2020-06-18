//
//  TestSignature448.swift
//  SwiftEdTests
//
//  Created by Leif Ibsen on 13/04/2020.
//

import XCTest

class TestSignature448: XCTestCase {

    // Test vectors from RFC 8032
    
    let secretKey1 = "6c82a562cb808d10d632be89c8513ebf6c929f34ddfa8c9f63c9960ef6e348a3528c8a3fcc2f044e39a3fc5b94492f8f032e7549a20098f95b"
    let publicKey1 = "5fd7449b59b461fd2ce787ec616ad46a1da1342485a70e1f8a0ea75d80e96778edf124769b46c7061bd6783df1e50f6cd1fa1abeafe8256180"
    let message1 = ""
    let context1 = ""
    let signature1 = "533a37f6bbe457251f023c0d88f976ae2dfb504a843e34d2074fd823d41a591f2b233f034f628281f2fd7a22ddd47d7828c59bd0a21bfd3980ff0d2028d4b18a9df63e006c5d1c2d345b925d8dc00b4104852db99ac5c7cdda8530a113a0f4dbb61149f05a7363268c71d95808ff2e652600"
    
    let secretKey2 = "c4eab05d357007c632f3dbb48489924d552b08fe0c353a0d4a1f00acda2c463afbea67c5e8d2877c5e3bc397a659949ef8021e954e0a12274e"
    let publicKey2 = "43ba28f430cdff456ae531545f7ecd0ac834a55d9358c0372bfa0c6c6798c0866aea01eb00742802b8438ea4cb82169c235160627b4c3a9480"
    let message2 = "03"
    let context2 = ""
    let signature2 = "26b8f91727bd62897af15e41eb43c377efb9c610d48f2335cb0bd0087810f4352541b143c4b981b7e18f62de8ccdf633fc1bf037ab7cd779805e0dbcc0aae1cbcee1afb2e027df36bc04dcecbf154336c19f0af7e0a6472905e799f1953d2a0ff3348ab21aa4adafd1d234441cf807c03a00"

    let secretKey3 = "c4eab05d357007c632f3dbb48489924d552b08fe0c353a0d4a1f00acda2c463afbea67c5e8d2877c5e3bc397a659949ef8021e954e0a12274e"
    let publicKey3 = "43ba28f430cdff456ae531545f7ecd0ac834a55d9358c0372bfa0c6c6798c0866aea01eb00742802b8438ea4cb82169c235160627b4c3a9480"
    let message3 = "03"
    let context3 = "666f6f"
    let signature3 = "d4f8f6131770dd46f40867d6fd5d5055de43541f8c5e35abbcd001b32a89f7d2151f7647f11d8ca2ae279fb842d607217fce6e042f6815ea000c85741de5c8da1144a6a1aba7f96de42505d7a7298524fda538fccbbb754f578c1cad10d54d0d5428407e85dcbc98a49155c13764e66c3c00"

    let secretKey4 = "cd23d24f714274e744343237b93290f511f6425f98e64459ff203e8985083ffdf60500553abc0e05cd02184bdb89c4ccd67e187951267eb328"
    let publicKey4 = "dcea9e78f35a1bf3499a831b10b86c90aac01cd84b67a0109b55a36e9328b1e365fce161d71ce7131a543ea4cb5f7e9f1d8b00696447001400"
    let message4 = "0c3e544074ec63b0265e0c"
    let context4 = ""
    let signature4 = "1f0a8888ce25e8d458a21130879b840a9089d999aaba039eaf3e3afa090a09d389dba82c4ff2ae8ac5cdfb7c55e94d5d961a29fe0109941e00b8dbdeea6d3b051068df7254c0cdc129cbe62db2dc957dbb47b51fd3f213fb8698f064774250a5028961c9bf8ffd973fe5d5c206492b140e00"

    let secretKey5 = "258cdd4ada32ed9c9ff54e63756ae582fb8fab2ac721f2c8e676a72768513d939f63dddb55609133f29adf86ec9929dccb52c1c5fd2ff7e21b"
    let publicKey5 = "3ba16da0c6f2cc1f30187740756f5e798d6bc5fc015d7c63cc9510ee3fd44adc24d8e968b6e46e6f94d19b945361726bd75e149ef09817f580"
    let message5 = "64a65f3cdedcdd66811e2915"
    let context5 = ""
    let signature5 = "7eeeab7c4e50fb799b418ee5e3197ff6bf15d43a14c34389b59dd1a7b1b85b4ae90438aca634bea45e3a2695f1270f07fdcdf7c62b8efeaf00b45c2c96ba457eb1a8bf075a3db28e5c24f6b923ed4ad747c3c9e03c7079efb87cb110d3a99861e72003cbae6d6b8b827e4e6c143064ff3c00"

    let secretKey6 = "7ef4e84544236752fbb56b8f31a23a10e42814f5f55ca037cdcc11c64c9a3b2949c1bb60700314611732a6c2fea98eebc0266a11a93970100e"
    let publicKey6 = "b3da079b0aa493a5772029f0467baebee5a8112d9d3a22532361da294f7bb3815c5dc59e176b4d9f381ca0938e13c6c07b174be65dfa578e80"
    let message6 = "64a65f3cdedcdd66811e2915e7"
    let context6 = ""
    let signature6 = "6a12066f55331b6c22acd5d5bfc5d71228fbda80ae8dec26bdd306743c5027cb4890810c162c027468675ecf645a83176c0d7323a2ccde2d80efe5a1268e8aca1d6fbc194d3f77c44986eb4ab4177919ad8bec33eb47bbb5fc6e28196fd1caf56b4e7e0ba5519234d047155ac727a1053100"

    let secretKey7 = "d65df341ad13e008567688baedda8e9dcdc17dc024974ea5b4227b6530e339bff21f99e68ca6968f3cca6dfe0fb9f4fab4fa135d5542ea3f01"
    let publicKey7 = "df9705f58edbab802c7f8363cfe5560ab1c6132c20a9f1dd163483a26f8ac53a39d6808bf4a1dfbd261b099bb03b3fb50906cb28bd8a081f00"
    let message7 = "bd0f6a3747cd561bdddf4640a332461a4a30a12a434cd0bf40d766d9c6d458e5512204a30c17d1f50b5079631f64eb3112182da3005835461113718d1a5ef944"
    let context7 = ""
    let signature7 = "554bc2480860b49eab8532d2a533b7d578ef473eeb58c98bb2d0e1ce488a98b18dfde9b9b90775e67f47d4a1c3482058efc9f40d2ca033a0801b63d45b3b722ef552bad3b4ccb667da350192b61c508cf7b6b5adadc2c8d9a446ef003fb05cba5f30e88e36ec2703b349ca229c2670833900"

    let secretKey8 = "2ec5fe3c17045abdb136a5e6a913e32ab75ae68b53d2fc149b77e504132d37569b7e766ba74a19bd6162343a21c8590aa9cebca9014c636df5"
    let publicKey8 = "79756f014dcfe2079f5dd9e718be4171e2ef2486a08f25186f6bff43a9936b9bfe12402b08ae65798a3d81e22e9ec80e7690862ef3d4ed3a00"
    let message8 = "15777532b0bdd0d1389f636c5f6b9ba734c90af572877e2d272dd078aa1e567cfa80e12928bb542330e8409f3174504107ecd5efac61ae7504dabe2a602ede89e5cca6257a7c77e27a702b3ae39fc769fc54f2395ae6a1178cab4738e543072fc1c177fe71e92e25bf03e4ecb72f47b64d0465aaea4c7fad372536c8ba516a6039c3c2a39f0e4d832be432dfa9a706a6e5c7e19f397964ca4258002f7c0541b590316dbc5622b6b2a6fe7a4abffd96105eca76ea7b98816af0748c10df048ce012d901015a51f189f3888145c03650aa23ce894c3bd889e030d565071c59f409a9981b51878fd6fc110624dcbcde0bf7a69ccce38fabdf86f3bef6044819de11"
    let context8 = ""
    let signature8 = "c650ddbb0601c19ca11439e1640dd931f43c518ea5bea70d3dcde5f4191fe53f00cf966546b72bcc7d58be2b9badef28743954e3a44a23f880e8d4f1cfce2d7a61452d26da05896f0a50da66a239a8a188b6d825b3305ad77b73fbac0836ecc60987fd08527c1a8e80d5823e65cafe2a3d00"

    func hex2bytes(_ x: String) -> Bytes {
        let b = [Byte](x.utf8)
        var bytes = Bytes(repeating: 0, count: b.count / 2)
        for i in 0 ..< bytes.count {
            let b0 = b[2 * i]
            let b1 = b[2 * i + 1]
            bytes[i] = ((b0 > 57 ? b0 - 97 + 10 : b0 - 48) << 4) | (b1 > 57 ? b1 - 97 + 10 : b1 - 48)
        }
        return bytes
    }

    func doTest1(_ secretKey: String, _ publicKey: String, _ message: String, _ context: String, _ signature: String) throws {
        let privKey = try PrivateKey(s: hex2bytes(secretKey))
        let pubKey = PublicKey(privateKey: privKey)
        XCTAssertEqual(pubKey.r, hex2bytes(publicKey))
        let sig = try privKey.sign(message: hex2bytes(message), context: hex2bytes(context))
        XCTAssertEqual(sig, hex2bytes(signature))
        XCTAssert(pubKey.verify(signature: sig, message: hex2bytes(message), context: hex2bytes(context)))
    }

    func doTest2(_ secretKey: String, _ publicKey: String) throws {
        let privKey = try PrivateKey(s: hex2bytes(secretKey))
        let pubKey1 = try PublicKey(r: hex2bytes(publicKey))
        let pubKey = try PublicKey(r: pubKey1.r)
        XCTAssertTrue(Ed.keyPairIsValid(r: pubKey.r, s: privKey.s))
    }

    func doTest4(_ secretKey: String, _ publicKey: String) throws {
        let privKey = try PrivateKey(s: hex2bytes(secretKey))
        let pubKey = try PublicKey(r: hex2bytes(publicKey))
        let sig = try privKey.sign(message: [], context: [1, 2, 3])
        XCTAssertTrue(pubKey.verify(signature: sig, message: [], context: [1, 2, 3]))
        XCTAssertFalse(pubKey.verify(signature: sig, message: [], context: [1, 2, 3, 4]))
    }

    func test1() throws {
        try doTest1(secretKey1, publicKey1, message1, context1, signature1)
        try doTest1(secretKey2, publicKey2, message2, context2, signature2)
        try doTest1(secretKey3, publicKey3, message3, context3, signature3)
        try doTest1(secretKey4, publicKey4, message4, context4, signature4)
        try doTest1(secretKey5, publicKey5, message5, context5, signature5)
        try doTest1(secretKey6, publicKey6, message6, context6, signature6)
        try doTest1(secretKey7, publicKey7, message7, context7, signature7)
        try doTest1(secretKey8, publicKey8, message8, context8, signature8)
    }
    
    func test2() throws {
        try doTest2(secretKey1, publicKey1)
        try doTest2(secretKey2, publicKey2)
        try doTest2(secretKey3, publicKey3)
        try doTest2(secretKey4, publicKey4)
        try doTest2(secretKey5, publicKey5)
        try doTest2(secretKey6, publicKey6)
        try doTest2(secretKey7, publicKey7)
        try doTest2(secretKey8, publicKey8)
    }
  
    func test3() {
        XCTAssertTrue(Ed.keyPairIsValid(r: hex2bytes(publicKey1), s: hex2bytes(secretKey1)))
        XCTAssertFalse(Ed.keyPairIsValid(r: hex2bytes(publicKey1), s: hex2bytes(secretKey2)))
        XCTAssertTrue(Ed.keyPairIsValid(r: hex2bytes(publicKey2), s: hex2bytes(secretKey2)))
        XCTAssertFalse(Ed.keyPairIsValid(r: hex2bytes(publicKey2), s: hex2bytes(secretKey1)))
        XCTAssertTrue(Ed.keyPairIsValid(r: hex2bytes(publicKey3), s: hex2bytes(secretKey3)))
        XCTAssertFalse(Ed.keyPairIsValid(r: hex2bytes(publicKey3), s: hex2bytes(secretKey1)))
        XCTAssertTrue(Ed.keyPairIsValid(r: hex2bytes(publicKey4), s: hex2bytes(secretKey4)))
        XCTAssertFalse(Ed.keyPairIsValid(r: hex2bytes(publicKey4), s: hex2bytes(secretKey1)))
        XCTAssertTrue(Ed.keyPairIsValid(r: hex2bytes(publicKey5), s: hex2bytes(secretKey5)))
        XCTAssertFalse(Ed.keyPairIsValid(r: hex2bytes(publicKey5), s: hex2bytes(secretKey1)))
        XCTAssertTrue(Ed.keyPairIsValid(r: hex2bytes(publicKey6), s: hex2bytes(secretKey6)))
        XCTAssertFalse(Ed.keyPairIsValid(r: hex2bytes(publicKey6), s: hex2bytes(secretKey1)))
        XCTAssertTrue(Ed.keyPairIsValid(r: hex2bytes(publicKey7), s: hex2bytes(secretKey7)))
        XCTAssertFalse(Ed.keyPairIsValid(r: hex2bytes(publicKey7), s: hex2bytes(secretKey1)))
        XCTAssertTrue(Ed.keyPairIsValid(r: hex2bytes(publicKey8), s: hex2bytes(secretKey8)))
        XCTAssertFalse(Ed.keyPairIsValid(r: hex2bytes(publicKey8), s: hex2bytes(secretKey1)))
    }

    func test4() throws {
        try doTest4(secretKey1, publicKey1)
        try doTest4(secretKey2, publicKey2)
        try doTest4(secretKey3, publicKey3)
    }

    // wycheproof test vectors

    let wpPublicKey = "419610a534af127f583b04818cdb7f0ff300b025f2e01682bcae33fd691cee039511df0cddc690ee978426e8b38e50ce5af7dcfba50f704c00"
    let wpSecretKey = "88301e076518d3537f9302ee0f5223e4b63e1f016007d3c2ebdfec5f70997e8119c6bad0ae7b803f48791ca8ec549aa2a1b862f7a51590b9d5"
    let wpMessage1 = ""
    let wpSignature1 = "cf7953007666e12f73af9ec92e3e018da5ee5a8d5b17f5100a354c58f1d5f4bb37ab835c52f72374c72d612689149cf6d36a70db6dc5a6c400b597348e0e31e51e65bb144e63c892a367b4c055c036aa6cd7e728cdd2a098963bda863903e6dd025b5a5d891209f4e28537694804e50b0800"
    let wpMessage2 = "78"
    let wpSignature2 = "c56e94d5c9ca860c244f33db556bf6b3cec38b024b77604a35d6a07211b1316b9a027133c374b86f72665cc45ce01583a2e0f2775c6172da801acef168717cab1196cddfb149359dfef589756257cc2d6b02fc516d8d41b4adaa3f11428f41410ef0dc3c1b008d3d052173d4389508ed0100"
    let wpMessage3 = "54657374"
    let wpSignature3 = "5d053ff5b71f6ec3284525d35d77933178c8e19879886d08eccc6c7d27e9e5b5e02537dbc4d4723506e8d171fc1733857573dd02d18f48f28031d67d699a188a9ca46b4eabe2107aef237ca609cb462e24c91d25d286402b6ef7862b78a386950246ff38d6d2f458136d12e3c97fdd982600"
    let wpMessage4 = "48656c6c6f"
    let wpSignature4 = "442e33780f199dd7bc71d1335f74df7f3a0ec789e21a175c1bffddb6e50091998d969ac8194b3acefb7702f6c222f84f7eeca3b80406f1fe80687915e7925bf52deb47b6b779e26d30eec7c5fef03580f280a089eefd0bacc9fbbb6a4d73a591d1671d192e6bbcfdb79ad3db5673a1263000"
    let wpMessage5 = "313233343030"
    let wpSignature5 = "5db94c53101f521f6c1f43b60ea4d7e06fbd49c2e8afaf4fcc289e645e0880a87b8e55858df4cf2291a7303ffda446b82a117b4dd408cff28060a05236fc9c1682b0e55b60a082c9a57bffe61ef4dda5ce65df539805122b3a09a05976d41ad68ab52df85428152c57da93531e5d16920e00"
    let wpMessage6 = "000000000000000000000000"
    let wpSignature6 = "a8ca64d1ab00eae77fd2854d8422db3ae12fca91c14f274f30a44df98590786ec4cbb96a9564fc1b9b16c22d2bd00aa65f0876323729f5ac809fb0b89a4d3f27afbabb596851d835173d60ea34e0875359f3d6adb13cef1395b7eaa5f9147583ff38b4deb183062874915bf194ae61072300"
    let wpMessage7 =  "6161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161"
    let wpSignature7 = "b205d3e24ccef64c1e86f15f48ddfa682453503489475188b04a8f55860b3c8a9c01e6de820bb7d9b15daff8de25a4a870e987157a115ec1802da0d0606da12842ea7eab658b5eea6dd1f3a641a5174425578003cd318b8d6b8dcb4de954b5078d1912c578ad8281515d6df3672b94173f00"
     
    func test5() throws {
         try doTest1(wpSecretKey, wpPublicKey, wpMessage1, "", wpSignature1)
         try doTest1(wpSecretKey, wpPublicKey, wpMessage2, "", wpSignature2)
         try doTest1(wpSecretKey, wpPublicKey, wpMessage3, "", wpSignature3)
         try doTest1(wpSecretKey, wpPublicKey, wpMessage4, "", wpSignature4)
         try doTest1(wpSecretKey, wpPublicKey, wpMessage5, "", wpSignature5)
         try doTest1(wpSecretKey, wpPublicKey, wpMessage6, "", wpSignature6)
         try doTest1(wpSecretKey, wpPublicKey, wpMessage7, "", wpSignature7)
     }

}
