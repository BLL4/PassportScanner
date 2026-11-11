import Foundation

/// Arithmetic modulo an odd number using Montgomery multiplication on 64-bit limbs.
/// Values are little-endian limb arrays of exactly `k` limbs. Not constant time; it is
/// only used for ephemeral protocol keys and public-key signature verification.
final class ModArith {
    typealias Limbs = [UInt64]

    let k: Int
    let modulus: Limbs
    let modulusBytes: Bytes
    private let nPrime: UInt64
    private let r2: Limbs
    /// 1 in Montgomery form (R mod m).
    let one: Limbs
    let zero: Limbs

    init(modulus bytesBE: Bytes) {
        let m = ModArith.limbs(fromBigEndian: bytesBE)
        precondition(m[0] & 1 == 1, "modulus must be odd")
        k = m.count
        modulus = m
        modulusBytes = Array(bytesBE.drop(while: { $0 == 0 }))
        zero = Limbs(repeating: 0, count: k)

        // -m^-1 mod 2^64 by Newton iteration.
        var inv: UInt64 = 1
        for _ in 0..<7 { inv = inv &* (2 &- m[0] &* inv) }
        nPrime = 0 &- inv

        // R mod m and R^2 mod m by repeated doubling.
        var x = Limbs(repeating: 0, count: k)
        x[0] = 1
        for _ in 0..<(64 * k) { x = ModArith.doubleMod(x, m) }
        one = x
        for _ in 0..<(64 * k) { x = ModArith.doubleMod(x, m) }
        r2 = x
    }

    // MARK: conversions

    static func limbs(fromBigEndian bytes: Bytes, count: Int? = nil) -> Limbs {
        let trimmed = Array(bytes.drop(while: { $0 == 0 }))
        let n = count ?? max(1, (trimmed.count + 7) / 8)
        var out = Limbs(repeating: 0, count: n)
        for (i, b) in trimmed.reversed().enumerated() where i / 8 < n {
            out[i / 8] |= UInt64(b) << (8 * UInt64(i % 8))
        }
        return out
    }

    static func bigEndianBytes(_ limbs: Limbs, length: Int) -> Bytes {
        var out = Bytes(repeating: 0, count: length)
        for i in 0..<length {
            let limb = i / 8
            guard limb < limbs.count else { break }
            out[length - 1 - i] = UInt8(truncatingIfNeeded: limbs[limb] >> (8 * UInt64(i % 8)))
        }
        return out
    }

    /// Plain integer (any value < 2^(64k)) to Montgomery form, reduced mod m.
    func toMont(_ bytesBE: Bytes) -> Limbs {
        mul(ModArith.limbs(fromBigEndian: bytesBE, count: k), r2)
    }

    func fromMont(_ a: Limbs) -> Bytes {
        var oneLimbs = zero
        oneLimbs[0] = 1
        return ModArith.bigEndianBytes(mul(a, oneLimbs), length: modulusBytes.count)
    }

    /// Reduces a plain integer below 2^(64k) modulo m, returning plain big-endian bytes.
    func reduce(_ bytesBE: Bytes) -> Bytes { fromMont(toMont(bytesBE)) }

    // MARK: arithmetic

    static func compare(_ a: Limbs, _ b: Limbs) -> Int {
        for i in stride(from: a.count - 1, through: 0, by: -1) where a[i] != b[i] {
            return a[i] < b[i] ? -1 : 1
        }
        return 0
    }

    private static func subInPlace(_ a: inout Limbs, _ b: Limbs) -> UInt64 {
        var borrow: UInt64 = 0
        for i in 0..<a.count {
            let (d1, o1) = a[i].subtractingReportingOverflow(b[i])
            let (d2, o2) = d1.subtractingReportingOverflow(borrow)
            a[i] = d2
            borrow = (o1 ? 1 : 0) + (o2 ? 1 : 0)
        }
        return borrow
    }

    private static func addInPlace(_ a: inout Limbs, _ b: Limbs) -> UInt64 {
        var carry: UInt64 = 0
        for i in 0..<a.count {
            let (s1, o1) = a[i].addingReportingOverflow(b[i])
            let (s2, o2) = s1.addingReportingOverflow(carry)
            a[i] = s2
            carry = (o1 ? 1 : 0) + (o2 ? 1 : 0)
        }
        return carry
    }

    private static func doubleMod(_ a: Limbs, _ m: Limbs) -> Limbs {
        var r = a
        let carry = addInPlace(&r, a)
        if carry != 0 || compare(r, m) >= 0 { _ = subInPlace(&r, m) }
        return r
    }

    func add(_ a: Limbs, _ b: Limbs) -> Limbs {
        var r = a
        let carry = ModArith.addInPlace(&r, b)
        if carry != 0 || ModArith.compare(r, modulus) >= 0 { _ = ModArith.subInPlace(&r, modulus) }
        return r
    }

    func sub(_ a: Limbs, _ b: Limbs) -> Limbs {
        var r = a
        if ModArith.subInPlace(&r, b) != 0 { _ = ModArith.addInPlace(&r, modulus) }
        return r
    }

    func neg(_ a: Limbs) -> Limbs { sub(zero, a) }

    func isZero(_ a: Limbs) -> Bool { a.allSatisfy { $0 == 0 } }

    /// Montgomery product a*b*R^-1 mod m (CIOS).
    func mul(_ a: Limbs, _ b: Limbs) -> Limbs {
        var t = Limbs(repeating: 0, count: k + 2)
        for i in 0..<k {
            var c: UInt64 = 0
            let bi = b[i]
            for j in 0..<k {
                (c, t[j]) = ModArith.mac(a[j], bi, t[j], c)
            }
            var (s, o) = t[k].addingReportingOverflow(c)
            t[k] = s
            t[k + 1] = o ? 1 : 0

            let mm = t[0] &* nPrime
            (c, _) = ModArith.mac(mm, modulus[0], t[0], 0)
            for j in 1..<k {
                (c, t[j - 1]) = ModArith.mac(mm, modulus[j], t[j], c)
            }
            (s, o) = t[k].addingReportingOverflow(c)
            t[k - 1] = s
            t[k] = t[k + 1] &+ (o ? 1 : 0)
        }
        var r = Array(t[0..<k])
        if t[k] != 0 || ModArith.compare(r, modulus) >= 0 { _ = ModArith.subInPlace(&r, modulus) }
        return r
    }

    /// a*b + c + d as a 128-bit (hi, lo) pair; cannot overflow.
    @inline(__always)
    private static func mac(_ a: UInt64, _ b: UInt64, _ c: UInt64, _ d: UInt64) -> (UInt64, UInt64) {
        let (h, l) = a.multipliedFullWidth(by: b)
        let (l1, o1) = l.addingReportingOverflow(c)
        let (l2, o2) = l1.addingReportingOverflow(d)
        return (h &+ (o1 ? 1 : 0) &+ (o2 ? 1 : 0), l2)
    }

    /// a^e for a in Montgomery form and a plain big-endian exponent.
    func pow(_ a: Limbs, _ exponentBE: Bytes) -> Limbs {
        var result = one
        for byte in exponentBE {
            for bit in stride(from: 7, through: 0, by: -1) {
                result = mul(result, result)
                if (byte >> UInt8(bit)) & 1 == 1 { result = mul(result, a) }
            }
        }
        return result
    }

    /// Inverse of a (Montgomery form) for a prime modulus, via Fermat.
    func inverse(_ a: Limbs) -> Limbs {
        var e = ModArith.limbs(fromBigEndian: modulusBytes, count: k)
        var two = Limbs(repeating: 0, count: k)
        two[0] = 2
        _ = ModArith.subInPlace(&e, two)
        return pow(a, ModArith.bigEndianBytes(e, length: modulusBytes.count))
    }
}
