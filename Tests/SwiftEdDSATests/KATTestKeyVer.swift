//
//  Created by Leif Ibsen on 11/09/2023.
//

import XCTest
@testable import SwiftEdDSA
import Digest

// KAT test vectors from NIST ACVP-server version 1.1.0.38.

final class KATTestKeyVer: XCTestCase {

    override func setUpWithError() throws {
        let url = Bundle.module.url(forResource: "katTestKeyVer", withExtension: "rsp")!
        makeKeyVerTests(try Data(contentsOf: url))
    }

    struct keyVerTest {
        let tcId: String
        let passed: Bool
        let d: Bytes
        let q: Bytes
    }
    
    var keyVerTests: [keyVerTest] = []

    func makeKeyVerTests(_ data: Data) {
        let s = String(decoding: data, as: UTF8.self)
        var lines = s.components(separatedBy: .newlines)
        let groups = lines.count / 5
        for i in 0 ..< groups {
            let j = i * 5
            lines[j].removeFirst(7)
            lines[j + 1].removeFirst(13)
            lines[j + 2].removeFirst(4)
            lines[j + 3].removeFirst(4)
        }
        for i in 0 ..< groups {
            let j = i * 5
            let tcId = lines[j]
            let passed = lines[j + 1] == "true"
            let d = Base64.hex2bytes(lines[j + 2])!
            let q = Base64.hex2bytes(lines[j + 3])!
            keyVerTests.append(keyVerTest(tcId: tcId, passed: passed, d: d, q: q))
        }
    }

    func testKeyVer() throws {
        for t in keyVerTests {
            let privKey = try PrivateKey(s: t.d)
            if t.passed {
                let pubKey = PublicKey(privateKey: privKey)
                XCTAssertEqual(pubKey.r, t.q)
            } else {
                do {
                    _ = try PublicKey(r: t.q)
                    XCTFail("Expected Ed.Ex.decode exception")
                } catch Ed.Ex.decode {
                } catch {
                    XCTFail("Expected Ed.Ex.decode exception")
                }
            }
        }
    }

}
