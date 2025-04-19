//
//  Created by Leif Ibsen on 11/09/2023.
//

import XCTest
@testable import SwiftEdDSA
import Digest

// KAT test vectors from NIST ACVP-server version 1.1.0.38.

final class KATTestSigGen: XCTestCase {

    override func setUpWithError() throws {
        let url = Bundle.module.url(forResource: "katTestSigGen", withExtension: "rsp")!
        makeSigGenTests(try Data(contentsOf: url))
    }

    struct sigGenTest {
        let tcId: String
        let preHash: Bool
        let d: Bytes
        let message: Bytes
        let context: Bytes
        let signature: Bytes
    }
    
    var sigGenTests: [sigGenTest] = []

    func makeSigGenTests(_ data: Data) {
        let s = String(decoding: data, as: UTF8.self)
        var lines = s.components(separatedBy: .newlines)
        let groups = lines.count / 7
        for i in 0 ..< groups {
            let j = i * 7
            lines[j].removeFirst(7)
            lines[j + 1].removeFirst(10)
            lines[j + 2].removeFirst(4)
            lines[j + 3].removeFirst(10)
            lines[j + 4].removeFirst(Swift.min(10, lines[j + 4].count))
            lines[j + 5].removeFirst(12)
        }
        for i in 0 ..< groups {
            let j = i * 7
            let tcId = lines[j]
            let preHash = lines[j + 1] == "true"
            let d = Base64.hex2bytes(lines[j + 2])!
            let message = Base64.hex2bytes(lines[j + 3])!
            let context = Base64.hex2bytes(lines[j + 4])!
            let signature = Base64.hex2bytes(lines[j + 5])!
            sigGenTests.append(sigGenTest(tcId: tcId, preHash: preHash, d: d, message: message, context: context, signature: signature))
        }
    }
    
    func testSigGen() throws {
        for t in sigGenTests {
            let privKey = try PrivateKey(s: t.d)
            var signature: Bytes
            if t.preHash {
                signature = try privKey.signPH(message: t.message, context: t.context, deterministic: true)
            } else {
                signature = try privKey.sign(message: t.message, context: t.context, deterministic: true)
            }
            XCTAssertEqual(signature, t.signature)
        }
    }

}
