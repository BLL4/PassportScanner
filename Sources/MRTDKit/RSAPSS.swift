import Foundation

/// RSASSA-PSS verification (RFC 8017, section 8.1.2) with arbitrary salt lengths. Apple's Security
/// framework only accepts salt length == hash length, but many CSCA / DS certificates use the
/// ASN.1 default of 20 bytes.
enum RSAPSS {
    /// - Parameters:
    ///   - publicKey: DER RSAPublicKey (SEQUENCE { modulus, publicExponent }).
    ///   - params: RSASSA-PSS-params SEQUENCE, or nil for the defaults (SHA-1, MGF1-SHA-1, salt 20).
    static func verify(publicKey: Bytes, params: TLV?, message: Bytes, signature: Bytes) -> Bool {
        guard let (key, _) = try? TLV.parse(publicKey), key.children.count == 2 else { return false }
        let n = ASN1.unsignedInteger(key.children[0].value), e = ASN1.unsignedInteger(key.children[1].value)
        guard n.count >= 64, n.last.map({ $0 & 1 == 1 }) == true else { return false }

        var hash = HashAlgorithm.sha1, mgfHash = HashAlgorithm.sha1, saltLength = 20
        for p in params?.children ?? [] {
            switch p.tag {
            case 0xA0:
                if let oid = p.child(0x30)?.child(0x06), let h = HashAlgorithm(oid: ASN1.decodeOID(oid.value)) { hash = h }
            case 0xA1:
                if let oid = p.child(0x30)?.child(0x30)?.child(0x06), let h = HashAlgorithm(oid: ASN1.decodeOID(oid.value)) { mgfHash = h }
            case 0xA2:
                if let v = ASN1.intValue(p.child(0x02)) { saltLength = v }
            default: break
            }
        }

        // RSAVP1: m = s^e mod n
        let ring = ModArith(modulus: n)
        let s = ASN1.unsignedInteger(signature)
        guard ModArith.compare(ModArith.limbs(fromBigEndian: s, count: ring.k), ring.modulus) < 0 else { return false }
        let em0 = ring.fromMont(ring.pow(ring.toMont(s), e))

        let modBits = n.count * 8 - n[0].leadingZeroBitCount
        let emBits = modBits - 1
        let emLen = (emBits + 7) / 8
        let em = Array(em0.suffix(emLen))
        guard em0.count - emLen == 0 || em0.first == 0 else { return false }

        let hLen = hash.hash([]).count
        guard emLen >= hLen + saltLength + 2, em.last == 0xBC else { return false }
        let maskedDB = Array(em[0..<(emLen - hLen - 1)])
        let h = Array(em[(emLen - hLen - 1)..<(emLen - 1)])
        let unusedBits = 8 * emLen - emBits
        guard maskedDB[0] >> UInt8(8 - unusedBits) == 0 || unusedBits == 0 else { return false }

        var mask = Bytes()
        var counter = 0
        while mask.count < maskedDB.count {
            mask += mgfHash.hash(h + bigEndian(counter, width: 4))
            counter += 1
        }
        var db = xor(maskedDB, Array(mask.prefix(maskedDB.count)))
        if unusedBits > 0 { db[0] &= UInt8(0xFF >> unusedBits) }
        let psLen = emLen - hLen - saltLength - 2
        guard db[0..<psLen].allSatisfy({ $0 == 0 }), db[psLen] == 0x01 else { return false }
        let salt = Array(db[(psLen + 1)...])
        return hash.hash(Bytes(repeating: 0, count: 8) + hash.hash(message) + salt) == h
    }
}
