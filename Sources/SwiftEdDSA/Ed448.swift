//
//  Ed448.swift
//  SwiftEd
//
//  Created by Leif Ibsen on 24/04/2020.
//

import BigInt

class Ed448 {

    // Not to be instantiated
    private init() {
    }

    static let P = (BInt.ONE << 448) - (BInt.ONE << 224) - 1
    static let L = BInt.ONE << 446 - BInt("13818066809895115352007386748515426880336692474882178609894547503885")!
    static let D = BInt("726838724295606890549323807888004534353641360687318060281490199180612328166730772686396383698676545930088884461843637361053498018326358")!

    // [RFC-8032] - section 5.2.3
    static func decode(_ b: Bytes) throws -> Point448 {
        let x0 = b[56] & 0x80 != 0
        var y = Ed.toBInt(b)
        y.clearBit(455)
        if y >= Ed448.P {
            throw Ed.Ex.decode
        }
        let y2 = y * y
        guard var x = ((y2 - BInt.ONE) * (Ed448.D * y2 - BInt.ONE).modInverse(Ed448.P)).sqrtMod(Ed448.P) else {
            throw Ed.Ex.decode
        }
        if x0 && x.isZero {
            throw Ed.Ex.decode
        }
        if (x0 && x.isEven) || (!x0 && x.isOdd) {
            x = Ed448.P - x
        }
        return Point448(x, y)
    }
    
    static func toBytes(_ x: BInt) -> Bytes {
        var b = Bytes(repeating: 0, count: 57)
        for i in 0 ..< x.magnitude.count {
            for j in 0 ..< 8 {
                b[i * 8 + j] = Byte((x.magnitude[i] >> (j << 3)) & 0xff)
            }
        }
        return b
    }

    static func dom4(_ x: Byte, _ context: Bytes) -> Bytes {
        return "SigEd448".utf8 + [x] + [Byte(context.count)] + context
    }

    // Barrett reduction

    static let uL = (BInt.ONE << 1024) / Ed448.L
    
    static func reduceModL(_ x: BInt) -> BInt {
        let t = x - ((x * Ed448.uL) >> 1024) * Ed448.L
        return t >= Ed448.L ? t - Ed448.L : t
    }

    static let uP = (BInt.ONE << 1024) / Ed448.P

    static func reduceModP(_ x: BInt) -> BInt {
        let t = x - ((x * Ed448.uP) >> 1024) * Ed448.P
        return t >= Ed448.P ? t - Ed448.P : t
    }

}
