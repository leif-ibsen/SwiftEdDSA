//
//  Ed25519.swift
//  SwiftEd
//
//  Created by Leif Ibsen on 28/03/2020.
//

import BigInt

class Ed25519 {

    // Not to be instantiated
    private init() {
    }

    static let P = BInt.ONE << 255 - 19
    static let L = BInt.ONE << 252 + BInt("27742317777372353535851937790883648493")!
    static let D = BInt("37095705934669439343138083508754565189542113879843219016388785533085940283555")!

    // [RFC-8032] - section 5.1.3
    static func decode(_ b: Bytes) throws -> Point25519 {
        let x0 = b[31] & 0x80 != 0
        var y = Ed.toBInt(b)
        y.clearBit(255)
        if y >= Ed25519.P {
            throw Ed.Ex.decode
        }
        let y2 = y * y
        guard var x = ((y2 - BInt.ONE) * (Ed25519.D * y2 + BInt.ONE).modInverse(Ed25519.P)).sqrtMod(Ed25519.P) else {
            throw Ed.Ex.decode
        }
        if x0 && x.isZero {
            throw Ed.Ex.decode
        }
        if (x0 && x.isEven) || (!x0 && x.isOdd) {
            x = Ed25519.P - x
        }
        return Point25519(x, y)
    }

    static func toBytes(_ x: BInt) -> Bytes {
        var b = Bytes(repeating: 0, count: 32)
        for i in 0 ..< x.magnitude.count {
            for j in 0 ..< 8 {
                b[i * 8 + j] = Byte((x.magnitude[i] >> (j << 3)) & 0xff)
            }
        }
        return b
    }

    static func dom2(_ x: Byte, _ context: Bytes) -> Bytes {
        return "SigEd25519 no Ed25519 collisions".utf8 + [x] + [Byte(context.count)] + context
    }

    // Barrett reduction

    static let uL = (BInt.ONE << 512) / Ed25519.L
    
    static func reduceModL(_ x: BInt) -> BInt {
        let t = x - ((x * Ed25519.uL) >> 512) * Ed25519.L
        return t >= Ed25519.L ? t - Ed25519.L : t
    }

    static let uP = (BInt.ONE << 512) / Ed25519.P

    static func reduceModP(_ x: BInt) -> BInt {
        let t = x - ((x * Ed25519.uP) >> 512) * Ed25519.P
        return t >= Ed25519.P ? t - Ed25519.P : t
    }

}
