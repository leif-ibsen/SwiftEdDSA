//
//  Created by Leif Ibsen on 11/09/2023.
//

import XCTest
@testable import SwiftEdDSA
import Digest

// KAT test vectors from NIST ACVP-server version 1.1.0.38.

final class KATTestKeyGen: XCTestCase {

    override func setUpWithError() throws {
        let url = Bundle.module.url(forResource: "katTestKeyGen", withExtension: "rsp")!
        makeKeyGenTests(try Data(contentsOf: url))
    }

    struct keyGenTest {
        let tcId: String
        let d: Bytes
        let q: Bytes
    }

    var keyGenTests: [keyGenTest] = []

    func makeKeyGenTests(_ data: Data) {
        let s = String(decoding: data, as: UTF8.self)
        var lines = s.components(separatedBy: .newlines)
        let groups = lines.count / 4
        for i in 0 ..< groups {
            let j = i * 4
            lines[j].removeFirst(7)
            lines[j + 1].removeFirst(4)
            lines[j + 2].removeFirst(4)
        }
        for i in 0 ..< groups {
            let j = i * 4
            let tcId = lines[j]
            let d = Base64.hex2bytes(lines[j + 1])!
            let q = Base64.hex2bytes(lines[j + 2])!
            keyGenTests.append(keyGenTest(tcId: tcId, d: d, q: q))
        }
    }

    func testKeyGen() throws {
        for t in keyGenTests {
            let privKey = try PrivateKey(s: t.d)
            let pubKey = PublicKey(privateKey: privKey)
            XCTAssertEqual(pubKey.r, t.q)
        }
    }

}
