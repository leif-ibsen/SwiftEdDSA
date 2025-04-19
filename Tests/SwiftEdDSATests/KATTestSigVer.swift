//
//  Created by Leif Ibsen on 11/09/2023.
//

import XCTest
@testable import SwiftEdDSA
import Digest

// KAT test vectors from NIST ACVP-server version 1.1.0.38.

final class KATTestSigVer: XCTestCase {

    override func setUpWithError() throws {
        let url = Bundle.module.url(forResource: "katTestSigVer", withExtension: "rsp")!
        makeSigVerTests(try Data(contentsOf: url))
    }

    struct sigVerTest {
        let tcId: String
        let preHash: Bool
        let q: Bytes
        let passed: Bool
        let message: Bytes
        let signature: Bytes
    }
    
    var sigVerTests: [sigVerTest] = []

    func makeSigVerTests(_ data: Data) {
        let s = String(decoding: data, as: UTF8.self)
        var lines = s.components(separatedBy: .newlines)
        let groups = lines.count / 7
        for i in 0 ..< groups {
            let j = i * 7
            lines[j].removeFirst(7)
            lines[j + 1].removeFirst(10)
            lines[j + 2].removeFirst(4)
            lines[j + 3].removeFirst(13)
            lines[j + 4].removeFirst(10)
            lines[j + 5].removeFirst(12)
        }
        for i in 0 ..< groups {
            let j = i * 7
            let tcId = lines[j]
            let preHash = lines[j + 1] == "true"
            let q = Base64.hex2bytes(lines[j + 2])!
            let passed = lines[j + 3] == "true"
            let message = Base64.hex2bytes(lines[j + 4])!
            let signature = Base64.hex2bytes(lines[j + 5])!
            sigVerTests.append(sigVerTest(tcId: tcId, preHash: preHash, q: q, passed: passed, message: message, signature: signature))
        }
    }
    
    func testSigVer() throws {
        for t in sigVerTests {
            let pubKey = try PublicKey(r: t.q)
            var ok: Bool
            if t.preHash {
                ok = pubKey.verifyPH(signature: t.signature, message: t.message)
            } else {
                ok = pubKey.verify(signature: t.signature, message: t.message)
            }
            XCTAssertEqual(ok, t.passed)
        }
    }

}
