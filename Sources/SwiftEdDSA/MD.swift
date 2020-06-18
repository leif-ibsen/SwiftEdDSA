//
//  MD.swift
//  SwiftEd
//
//  Created by Leif Ibsen on 28/03/2020.
//

class MD {
    
    let sha512: SHA2_512
    var totalBytes: Int
    var bytes: Int
    var buffer: Bytes
    var hl: [UInt64]
    
    init() {
        self.sha512 = SHA2_512()
        self.buffer = Bytes(repeating: 0, count: 128)
        self.hl = [UInt64](repeating: 0, count: 8)
        self.totalBytes = 0
        self.bytes = 0
        self.sha512.doReset(&self.hl)
    }

    func reset() {
        for i in 0 ..< self.buffer.count {
            self.buffer[i] = 0
        }
        self.totalBytes = 0
        self.bytes = 0
        self.sha512.doReset(&self.hl)
    }
    
    func update(_ input: Bytes) {
        var remaining = input.count
        var ndx = 0
        while remaining > 0 {
            let a = remaining < self.buffer.count - self.bytes ? remaining : self.buffer.count - self.bytes
            for i in 0 ..< a {
                self.buffer[self.bytes + i] = input[ndx + i]
            }
            self.bytes += a
            ndx += a
            remaining -= a
            if self.bytes == self.buffer.count {
                self.sha512.doBuffer(&self.buffer, &self.hl)
                self.bytes = 0
            }
        }
        self.totalBytes += input.count
    }
    
    func digest() -> Bytes {
        var md = Bytes(repeating: 0, count: 64)
        update(self.sha512.padding(self.totalBytes, self.buffer.count))
        for i in 0 ..< md.count {
            md[i] = Byte((self.hl[i >> 3] >> ((7 - (i & 0x7)) * 8)) & 0xff)
        }
        self.reset()
        return md
    }

    func digest2() -> (Bytes, Bytes) {
        var d = self.digest()
        d[0] &= 0xf8
        d[31] &= 0x7f
        d[31] |= 0x40
        return (Bytes(d[0 ..< 32]), Bytes(d[32 ..< 64]))
    }

}

// FIPS PUB 180-4, August 2015
class SHA2_512 {
    
    static let k: [UInt64] = [
        0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
        0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
        0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
        0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
        0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
        0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
        0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
        0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
        0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
        0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
        0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
        0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
        0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
        0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
        0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
        0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
        0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
        0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
        0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
        0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817 ]
    
    var l: [UInt64]
    
    init() {
        self.l = [UInt64](repeating: 0, count: 80)
    }
    
    func doReset(_ hl: inout [UInt64]) {
        hl[0] = 0x6a09e667f3bcc908
        hl[1] = 0xbb67ae8584caa73b
        hl[2] = 0x3c6ef372fe94f82b
        hl[3] = 0xa54ff53a5f1d36f1
        hl[4] = 0x510e527fade682d1
        hl[5] = 0x9b05688c2b3e6c1f
        hl[6] = 0x1f83d9abfb41bd6b
        hl[7] = 0x5be0cd19137e2179
    }
    
    func doBuffer(_ buffer: inout Bytes, _ hl: inout [UInt64]) {
        for i in 0 ..< l.count {
            l[i] = 0
        }
        for i in 0 ..< 16 {
            let index = 8 * i
            let l0 = UInt64(buffer[index]) << 56
            let l1 = UInt64(buffer[index + 1]) << 48
            let l2 = UInt64(buffer[index + 2]) << 40
            let l3 = UInt64(buffer[index + 3]) << 32
            let l4 = UInt64(buffer[index + 4]) << 24
            let l5 = UInt64(buffer[index + 5]) << 16
            let l6 = UInt64(buffer[index + 6]) << 8
            let l7 = UInt64(buffer[index + 7])
            self.l[i] = l0 | l1 | l2 | l3 | l4 | l5 | l6 | l7
        }
        for i in 16 ..< 80 {
            self.l[i] = SSIG1(self.l[i - 2]) &+ self.l[i - 7] &+ SSIG0(self.l[i - 15]) &+ self.l[i - 16]
        }
        var a = hl[0]
        var b = hl[1]
        var c = hl[2]
        var d = hl[3]
        var e = hl[4]
        var f = hl[5]
        var g = hl[6]
        var h = hl[7]
        for i in 0 ..< 80 {
            let t1 = h &+ BSIG1(e) &+ CH(e, f, g) &+ SHA2_512.k[i] &+ self.l[i]
            let t2 = BSIG0(a) &+ MAJ(a, b, c)
            h = g
            g = f
            f = e
            e = d &+ t1
            d = c
            c = b
            b = a
            a = t1 &+ t2
        }
        hl[0] &+= a
        hl[1] &+= b
        hl[2] &+= c
        hl[3] &+= d
        hl[4] &+= e
        hl[5] &+= f
        hl[6] &+= g
        hl[7] &+= h
    }
    
    func CH(_ x: UInt64, _ y: UInt64, _ z: UInt64) -> UInt64 {
        return (x & y) ^ ((~x) & z)
    }

    func MAJ(_ x: UInt64, _ y: UInt64, _ z: UInt64) -> UInt64 {
        return (x & y) ^ (x & z) ^ (y & z)
    }

    func BSIG0(_ x: UInt64) -> UInt64 {
        return SHA2_512.rotateRight(x, 28) ^ SHA2_512.rotateRight(x, 34) ^ SHA2_512.rotateRight(x, 39)
    }
    
    func BSIG1(_ x: UInt64) -> UInt64 {
        return SHA2_512.rotateRight(x, 14) ^ SHA2_512.rotateRight(x, 18) ^ SHA2_512.rotateRight(x, 41)
    }
    
    func SSIG0(_ x: UInt64) -> UInt64 {
        return SHA2_512.rotateRight(x, 1) ^ SHA2_512.rotateRight(x, 8) ^ (x >> 7)
    }
    
    func SSIG1(_ x: UInt64) -> UInt64 {
        return SHA2_512.rotateRight(x, 19) ^ SHA2_512.rotateRight(x, 61) ^ (x >> 6)
    }
    
    func padding(_ totalBytes: Int, _ blockSize: Int) -> Bytes {
        var l = totalBytes * 8
        let x = ((totalBytes + 16 + blockSize) / blockSize) * blockSize - totalBytes
        var b = Bytes(repeating: 0, count: x)
        b[0] = 0x80
        b[x - 1] = Byte(l & 0xff)
        l >>= 8
        b[x - 2] = Byte(l & 0xff)
        l >>= 8
        b[x - 3] = Byte(l & 0xff)
        l >>= 8
        b[x - 4] = Byte(l & 0xff)
        l >>= 8
        b[x - 5] = Byte(l & 0xff)
        l >>= 8
        b[x - 6] = Byte(l & 0xff)
        l >>= 8
        b[x - 7] = Byte(l & 0xff)
        l >>= 8
        b[x - 8] = Byte(l & 0xff)
        return b
    }
    
    static func rotateRight(_ x: UInt64, _ n: Int) -> UInt64 {
        return (x >> n) | (x << (64 - n))
    }

}
