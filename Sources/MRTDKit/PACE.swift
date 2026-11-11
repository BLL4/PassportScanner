import Foundation

/// A PACEInfo entry from EF.CardAccess.
public struct PACEInfo: CustomStringConvertible {
    public static let idPACE = "0.4.0.127.0.7.2.2.4"

    public let oid: String
    public let version: Int
    public let parameterID: Int?

    public enum Mapping: String { case dhGM = "DH-GM", ecdhGM = "ECDH-GM", dhIM = "DH-IM", ecdhIM = "ECDH-IM", ecdhCAM = "ECDH-CAM" }

    public var mapping: Mapping? {
        let parts = oid.split(separator: ".")
        guard parts.count == 11 else { return nil }
        switch parts[9] {
        case "1": return .dhGM
        case "2": return .ecdhGM
        case "3": return .dhIM
        case "4": return .ecdhIM
        case "6": return .ecdhCAM
        default: return nil
        }
    }

    public var cipher: SymmetricAlgorithm? {
        switch oid.split(separator: ".").last {
        case "1": return .tdes
        case "2": return .aes128
        case "3": return .aes192
        case "4": return .aes256
        default: return nil
        }
    }

    public var curve: ECCurve? { parameterID.flatMap(ECCurve.forPACEParameterID) }

    /// Whether this implementation can run the protocol.
    public var isSupported: Bool {
        (mapping == .ecdhGM || mapping == .ecdhCAM) && cipher != nil && curve != nil
    }

    public var description: String {
        "PACE \(mapping?.rawValue ?? "?") \(cipher?.rawValue ?? "?") \(curve?.name ?? parameterID.map { "param \($0)" } ?? "")"
    }

    /// Parses all PACEInfo entries from an EF.CardAccess (or DG14) SecurityInfos SET.
    public static func parse(cardAccess: Bytes) -> [PACEInfo] {
        guard let set = try? TLV.parseAll(cardAccess).first(where: { $0.tag == 0x31 }) else { return [] }
        return set.children.compactMap { seq in
            let items = seq.children
            guard items.count >= 2, items[0].tag == 0x06 else { return nil }
            let oid = ASN1.decodeOID(items[0].value)
            guard oid.hasPrefix(idPACE + "."), let version = ASN1.intValue(items[1]) else { return nil }
            let param = items.count > 2 ? ASN1.intValue(items[2]) : nil
            return PACEInfo(oid: oid, version: version, parameterID: param)
        }
    }
}

/// Password Authenticated Connection Establishment (ICAO 9303 part 11, section 4.4),
/// Generic Mapping on elliptic curves. Chip Authentication Mapping chips also accept
/// Generic Mapping steps, so CAM entries are run as GM (chip authentication is skipped).
enum PACE {
    static func passwordKey(_ key: AccessKey, algorithm: SymmetricAlgorithm) -> (Bytes, UInt8) {
        switch key {
        case .mrz(let mrz):
            return (deriveKey(HashAlgorithm.sha1.hash(Bytes(mrz.mrzInformation.utf8)), counter: 3, algorithm: algorithm), 0x01)
        case .can(let can):
            return (deriveKey(Bytes(can.utf8), counter: 3, algorithm: algorithm), 0x02)
        }
    }

    static func decryptNonce(_ z: Bytes, key: Bytes, algorithm: SymmetricAlgorithm) -> Bytes {
        algorithm.cipher.decryptCBC(key: key, iv: Bytes(repeating: 0, count: algorithm.blockSize), z)
    }

    /// Generic mapping: G' = s·G + H, where H is the ECDH result of the mapping key exchange.
    static func mapGenerator(group: ECGroup, nonce: Bytes, sharedPoint: ECPoint) -> ECPoint {
        group.add(group.multiply(nonce, group.generator), sharedPoint)
    }

    /// Public key data object 7F49 used as input to the authentication token.
    static func publicKeyDataObject(oid: String, point: Bytes) -> Bytes {
        TLV.encode(0x7F49, TLV.encode(0x06, ASN1.encodeOID(oid)) + TLV.encode(0x86, point))
    }

    static func authenticationToken(macKey: Bytes, algorithm: SymmetricAlgorithm, oid: String, point: Bytes) -> Bytes {
        let input = publicKeyDataObject(oid: oid, point: point)
        if algorithm == .tdes { return retailMAC(key: macKey, pad(input, blockSize: 8)) }
        return Array(aesCMAC(key: macKey, input).prefix(8))
    }

    private static func generalAuthenticate(_ chip: Chip, _ inner: Bytes, last: Bool, step: String) async throws -> TLV {
        let apdu = CommandAPDU(cla: last ? 0x00 : 0x10, ins: 0x86, p1: 0, p2: 0, data: TLV.encode(0x7C, inner), ne: 256)
        let r = try await chip.send(apdu, "GENERAL AUTHENTICATE (\(step))")
        guard r.isSuccess else {
            if r.sw == 0x6300 || r.sw & 0xFFF0 == 0x63C0 || (last && r.sw == 0x6982) {
                throw MRTDError.accessDenied(PassportReader.wrongKeyMessage(sw: r.sw))
            }
            throw MRTDError.status("GENERAL AUTHENTICATE (\(step))", r.sw)
        }
        guard let (t, _) = try? TLV.parse(r.data), t.tag == 0x7C else { throw MRTDError.malformed("PACE \(step) response") }
        return t
    }

    static func perform(chip: Chip, key: AccessKey, info: PACEInfo) async throws {
        guard info.isSupported, let algorithm = info.cipher, let curve = info.curve else {
            throw MRTDError.unsupported(info.description)
        }
        let group = curve.group
        let (kPi, passwordRef) = passwordKey(key, algorithm: algorithm)

        // MSE:Set AT selects the protocol and the password.
        let oidBytes = ASN1.encodeOID(info.oid)
        var mse = TLV.encode(0x80, oidBytes) + TLV.encode(0x83, [passwordRef])
        if let id = info.parameterID { mse += TLV.encode(0x84, [UInt8(id)]) }
        var r = try await chip.send(CommandAPDU(ins: 0x22, p1: 0xC1, p2: 0xA4, data: mse), "MSE:Set AT")
        if !r.isSuccess && info.parameterID != nil {
            mse = TLV.encode(0x80, oidBytes) + TLV.encode(0x83, [passwordRef])
            r = try await chip.send(CommandAPDU(ins: 0x22, p1: 0xC1, p2: 0xA4, data: mse), "MSE:Set AT")
        }
        guard r.isSuccess else { throw MRTDError.status("MSE:Set AT", r.sw) }

        // 1. Encrypted nonce.
        let t1 = try await generalAuthenticate(chip, [], last: false, step: "nonce")
        guard let z = t1.child(0x80)?.value else { throw MRTDError.malformed("PACE nonce") }
        let s = decryptNonce(z, key: kPi, algorithm: algorithm)

        // 2. Mapping.
        let map = group.makeKeyPair()
        let t2 = try await generalAuthenticate(chip, TLV.encode(0x81, group.encode(map.publicKey)), last: false, step: "map")
        guard let pkMapIC = t2.child(0x82).flatMap({ group.decode($0.value) }) else { throw MRTDError.malformed("PACE mapping key") }
        let h = group.multiply(map.privateKey, pkMapIC)
        guard !h.isInfinity else { throw MRTDError.malformed("PACE mapping produced the point at infinity") }
        let g2 = mapGenerator(group: group, nonce: s, sharedPoint: h)

        // 3. Key agreement on the mapped generator.
        let eph = group.makeKeyPair(generator: g2)
        let pkIFD = group.encode(eph.publicKey)
        let t3 = try await generalAuthenticate(chip, TLV.encode(0x83, pkIFD), last: false, step: "key agreement")
        guard let pkICBytes = t3.child(0x84)?.value, let pkIC = group.decode(pkICBytes), pkICBytes != pkIFD else {
            throw MRTDError.malformed("PACE ephemeral key")
        }
        let shared = group.multiply(eph.privateKey, pkIC)
        guard !shared.isInfinity else { throw MRTDError.malformed("PACE shared secret") }
        let kEnc = deriveKey(shared.x, counter: 1, algorithm: algorithm)
        let kMac = deriveKey(shared.x, counter: 2, algorithm: algorithm)

        // 4. Mutual authentication.
        let tIFD = authenticationToken(macKey: kMac, algorithm: algorithm, oid: info.oid, point: pkICBytes)
        let t4 = try await generalAuthenticate(chip, TLV.encode(0x85, tIFD), last: true, step: "mutual authentication")
        let expected = authenticationToken(macKey: kMac, algorithm: algorithm, oid: info.oid, point: pkIFD)
        guard t4.child(0x86)?.value == expected else { throw MRTDError.accessDenied("PACE: chip authentication token is invalid") }

        chip.sm = SecureMessaging(algorithm: algorithm, kEnc: kEnc, kMac: kMac,
                                  ssc: Bytes(repeating: 0, count: algorithm.blockSize))
    }
}
