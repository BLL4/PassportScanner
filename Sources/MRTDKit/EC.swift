import Foundation

/// Group operations on a prime-field elliptic curve, using Jacobian coordinates internally.
public final class ECGroup {
    typealias Limbs = ModArith.Limbs

    public let curve: ECCurve
    let field: ModArith
    let order: ModArith
    private let aM: Limbs
    private let bM: Limbs
    /// Length in bytes of a field element.
    public let fieldLength: Int
    public let generator: ECPoint

    private struct Jacobian {
        var x: Limbs, y: Limbs, z: Limbs
    }

    public init(_ curve: ECCurve) {
        self.curve = curve
        field = ModArith(modulus: curve.p)
        order = ModArith(modulus: curve.n)
        aM = field.toMont(curve.a)
        bM = field.toMont(curve.b)
        fieldLength = field.modulusBytes.count
        generator = ECPoint(x: leftPad(curve.gx, to: field.modulusBytes.count), y: leftPad(curve.gy, to: field.modulusBytes.count))
    }

    // MARK: encoding

    /// Uncompressed SEC1 encoding: 04 || X || Y.
    public func encode(_ p: ECPoint) -> Bytes { [0x04] + p.x + p.y }

    public func decode(_ bytes: Bytes) -> ECPoint? {
        guard bytes.count == 1 + 2 * fieldLength, bytes[0] == 0x04 else { return nil }
        let p = ECPoint(x: Array(bytes[1...fieldLength]), y: Array(bytes[(1 + fieldLength)...]))
        return isOnCurve(p) ? p : nil
    }

    public func isOnCurve(_ p: ECPoint) -> Bool {
        if p.isInfinity { return true }
        guard ModArith.compare(ModArith.limbs(fromBigEndian: p.x, count: field.k), field.modulus) < 0,
              ModArith.compare(ModArith.limbs(fromBigEndian: p.y, count: field.k), field.modulus) < 0
        else { return false }
        let x = field.toMont(p.x), y = field.toMont(p.y)
        let lhs = field.mul(y, y)
        let rhs = field.add(field.add(field.mul(field.mul(x, x), x), field.mul(aM, x)), bM)
        return lhs == rhs
    }

    // MARK: arithmetic

    private func toJacobian(_ p: ECPoint) -> Jacobian {
        if p.isInfinity { return Jacobian(x: field.one, y: field.one, z: field.zero) }
        return Jacobian(x: field.toMont(p.x), y: field.toMont(p.y), z: field.one)
    }

    private func toAffine(_ p: Jacobian) -> ECPoint {
        if field.isZero(p.z) { return .infinity }
        let zi = field.inverse(p.z)
        let zi2 = field.mul(zi, zi)
        let x = field.mul(p.x, zi2)
        let y = field.mul(p.y, field.mul(zi2, zi))
        return ECPoint(x: field.fromMont(x), y: field.fromMont(y))
    }

    private func double(_ p: Jacobian) -> Jacobian {
        if field.isZero(p.z) || field.isZero(p.y) { return Jacobian(x: field.one, y: field.one, z: field.zero) }
        let f = field
        let xx = f.mul(p.x, p.x)
        let yy = f.mul(p.y, p.y)
        let zz = f.mul(p.z, p.z)
        let yyyy = f.mul(yy, yy)
        var s = f.mul(p.x, yy)
        s = f.add(s, s); s = f.add(s, s)                    // 4·X·Y²
        var m = f.add(f.add(xx, xx), xx)
        m = f.add(m, f.mul(aM, f.mul(zz, zz)))              // 3·X² + a·Z⁴
        let x3 = f.sub(f.mul(m, m), f.add(s, s))
        var y8 = f.add(yyyy, yyyy); y8 = f.add(y8, y8); y8 = f.add(y8, y8)
        let y3 = f.sub(f.mul(m, f.sub(s, x3)), y8)
        let yz = f.mul(p.y, p.z)
        return Jacobian(x: x3, y: y3, z: f.add(yz, yz))
    }

    private func add(_ p: Jacobian, _ q: Jacobian) -> Jacobian {
        let f = field
        if f.isZero(p.z) { return q }
        if f.isZero(q.z) { return p }
        let z1z1 = f.mul(p.z, p.z), z2z2 = f.mul(q.z, q.z)
        let u1 = f.mul(p.x, z2z2), u2 = f.mul(q.x, z1z1)
        let s1 = f.mul(p.y, f.mul(q.z, z2z2)), s2 = f.mul(q.y, f.mul(p.z, z1z1))
        if u1 == u2 {
            return s1 == s2 ? double(p) : Jacobian(x: f.one, y: f.one, z: f.zero)
        }
        let h = f.sub(u2, u1), r = f.sub(s2, s1)
        let hh = f.mul(h, h), hhh = f.mul(hh, h)
        let v = f.mul(u1, hh)
        let x3 = f.sub(f.sub(f.mul(r, r), hhh), f.add(v, v))
        let y3 = f.sub(f.mul(r, f.sub(v, x3)), f.mul(s1, hhh))
        let z3 = f.mul(h, f.mul(p.z, q.z))
        return Jacobian(x: x3, y: y3, z: z3)
    }

    private func multiplyJ(_ scalar: Bytes, _ p: Jacobian) -> Jacobian {
        var r = Jacobian(x: field.one, y: field.one, z: field.zero)
        for byte in scalar {
            for bit in stride(from: 7, through: 0, by: -1) {
                r = double(r)
                if (byte >> UInt8(bit)) & 1 == 1 { r = add(r, p) }
            }
        }
        return r
    }

    public func multiply(_ scalar: Bytes, _ p: ECPoint) -> ECPoint {
        toAffine(multiplyJ(scalar, toJacobian(p)))
    }

    public func add(_ p: ECPoint, _ q: ECPoint) -> ECPoint {
        toAffine(add(toJacobian(p), toJacobian(q)))
    }

    // MARK: keys

    /// Uniformly random scalar in [1, n-1].
    public func randomScalar() -> Bytes {
        let len = order.modulusBytes.count
        let topBits = curve.n.drop(while: { $0 == 0 }).first.map { 8 - $0.leadingZeroBitCount } ?? 8
        let n = ModArith.limbs(fromBigEndian: curve.n, count: order.k)
        while true {
            var r = secureRandom(len)
            r[0] &= UInt8((1 << topBits) - 1)
            let l = ModArith.limbs(fromBigEndian: r, count: order.k)
            if ModArith.compare(l, n) < 0 && !l.allSatisfy({ $0 == 0 }) { return r }
        }
    }

    public func makeKeyPair(generator g: ECPoint? = nil) -> (privateKey: Bytes, publicKey: ECPoint) {
        let d = randomScalar()
        return (d, multiply(d, g ?? generator))
    }

    // MARK: ECDSA

    /// Verifies an ECDSA signature over a message digest.
    public func verify(digest: Bytes, r rIn: Bytes, s sIn: Bytes, publicKey q: ECPoint) -> Bool {
        let o = order
        let nLimbs = ModArith.limbs(fromBigEndian: curve.n, count: o.k)
        let r = ASN1.unsignedInteger(rIn), s = ASN1.unsignedInteger(sIn)
        guard r.count <= o.modulusBytes.count, s.count <= o.modulusBytes.count else { return false }
        let rL = ModArith.limbs(fromBigEndian: r, count: o.k), sL = ModArith.limbs(fromBigEndian: s, count: o.k)
        guard !o.isZero(rL), !o.isZero(sL), ModArith.compare(rL, nLimbs) < 0, ModArith.compare(sL, nLimbs) < 0 else { return false }
        guard !q.isInfinity, isOnCurve(q) else { return false }

        // e = leftmost bitlen(n) bits of the digest.
        let nBits = o.modulusBytes.count * 8 - (o.modulusBytes.first?.leadingZeroBitCount ?? 0)
        var e = digest
        if e.count * 8 > nBits {
            e = Array(e.prefix((nBits + 7) / 8))
            let excess = e.count * 8 - nBits
            if excess > 0 {
                var shifted = Bytes(repeating: 0, count: e.count)
                var carry: UInt8 = 0
                for i in 0..<e.count {
                    shifted[i] = (e[i] >> UInt8(excess)) | carry
                    carry = e[i] << UInt8(8 - excess)
                }
                e = shifted
            }
        }
        let eM = o.toMont(e)
        let w = o.inverse(o.toMont(s))
        let u1 = o.fromMont(o.mul(eM, w))
        let u2 = o.fromMont(o.mul(o.toMont(r), w))
        let point = toAffine(add(multiplyJ(u1, toJacobian(generator)), multiplyJ(u2, toJacobian(q))))
        guard !point.isInfinity else { return false }
        let v = o.reduce(point.x)
        return leftPad(v, to: o.modulusBytes.count) == leftPad(r, to: o.modulusBytes.count)
    }
}
