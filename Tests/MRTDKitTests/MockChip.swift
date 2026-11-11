import Foundation
@testable import MRTDKit

/// A simulated eMRTD chip implementing the chip side of BAC, PACE (ECDH-GM) and secure messaging.
final class MockChip: CardTransport {
    enum Mode { case bacOnly, pace(PACEInfo) }

    let mode: Mode
    let mrzKey: MRZKey
    let can: String
    var files: [UInt16: Bytes]
    var cardAccess: Bytes?
    private(set) var log: [String] = []

    private var sm: SecureMessaging?
    private var selected: UInt16?
    private var appSelected = false
    // BAC
    private var rndIC: Bytes?
    // PACE
    private var passwordRef: UInt8 = 0
    private var paceStep = 0
    private var nonce: Bytes = []
    private var group: ECGroup?
    private var mapKey: (privateKey: Bytes, publicKey: ECPoint)?
    private var mappedG: ECPoint?
    private var ephKey: (privateKey: Bytes, publicKey: ECPoint)?
    private var pkIFD: Bytes = []
    private var sessionKeys: (Bytes, Bytes)?

    init(mode: Mode, mrzKey: MRZKey, can: String = "123456", files: [UInt16: Bytes]) {
        self.mode = mode
        self.mrzKey = mrzKey
        self.can = can
        self.files = files
        if case .pace(let info) = mode {
            let oid = TLV.encode(0x06, ASN1.encodeOID(info.oid))
            let paceInfo = TLV.encode(0x30, oid + TLV.encode(0x02, [2]) + TLV.encode(0x02, [UInt8(info.parameterID!)]))
            cardAccess = TLV.encode(0x31, paceInfo)
        }
    }

    func transmit(_ raw: Bytes) async throws -> Bytes {
        var apdu = parse(raw)
        if let sm, apdu.cla & 0x0C == 0x0C {
            guard let plain = unwrap(apdu, sm) else { self.sm = nil; return [0x69, 0x88] }
            apdu = plain
            let resp = process(apdu)
            return wrap(resp, sm)
        } else if sm != nil {
            sm = nil
        }
        return process(apdu).encoded
    }

    private func parse(_ raw: Bytes) -> CommandAPDU {
        var a = CommandAPDU(cla: raw[0], ins: raw[1], p1: raw[2], p2: raw[3])
        if raw.count == 5 { a.ne = raw[4] == 0 ? 256 : Int(raw[4]) }
        if raw.count > 5 {
            let lc = Int(raw[4])
            a.data = Array(raw[5..<5 + lc])
            if raw.count > 5 + lc { a.ne = raw[5 + lc] == 0 ? 256 : Int(raw[5 + lc]) }
        }
        return a
    }

    private func unwrap(_ a: CommandAPDU, _ sm: SecureMessaging) -> CommandAPDU? {
        sm.incrementSSC()
        guard let objs = try? TLV.parseAll(a.data) else { return nil }
        var macInput = pad([a.cla, a.ins, a.p1, a.p2], blockSize: sm.blockSize)
        var data = Bytes(), ne: Int?
        var cc: Bytes?
        for o in objs {
            switch o.tag {
            case 0x87: macInput += o.encoded; data = sm.decrypt(Array(o.value.dropFirst()))
            case 0x85: macInput += o.encoded; data = unpad(sm.algorithm.cipher.decryptCBC(key: sm.kEnc, iv: ivFor(sm), o.value))
            case 0x97: macInput += o.encoded; ne = o.value == [0] ? 256 : intValue(o.value)
            case 0x8E: cc = o.value
            default: return nil
            }
        }
        guard cc == sm.mac(macInput) else { return nil }
        return CommandAPDU(cla: a.cla & ~0x0C, ins: a.ins, p1: a.p1, p2: a.p2, data: data, ne: ne)
    }

    private func ivFor(_ sm: SecureMessaging) -> Bytes {
        sm.algorithm == .tdes ? Bytes(repeating: 0, count: 8) : BlockCipher.aes.encryptECB(key: sm.kEnc, sm.ssc)
    }

    private func wrap(_ r: ResponseAPDU, _ sm: SecureMessaging) -> Bytes {
        sm.incrementSSC()
        var body = Bytes()
        if !r.data.isEmpty { body += TLV.encode(0x87, [0x01] + sm.encrypt(r.data)) }
        body += [0x99, 0x02, r.sw1, r.sw2]
        body += [0x8E, 0x08] + sm.mac(body)
        return body + [0x90, 0x00]
    }

    private func sw(_ v: UInt16, _ data: Bytes = []) -> ResponseAPDU {
        ResponseAPDU(data: data, sw1: UInt8(v >> 8), sw2: UInt8(v & 0xFF))
    }

    private func process(_ a: CommandAPDU) -> ResponseAPDU {
        log.append(String(format: "%02X", a.ins))
        switch a.ins {
        case 0xA4:
            if a.p1 == 0x04 {
                guard a.data == Chip.eMRTDApplicationID else { return sw(0x6A82) }
                appSelected = true
                return sw(0x9000)
            }
            if a.p1 == 0x02 {
                guard sm != nil else { return sw(0x6982) }
                let fid = UInt16(a.data[0]) << 8 | UInt16(a.data[1])
                guard files[fid] != nil else { return sw(0x6A82) }
                selected = fid
                return sw(0x9000)
            }
            return sw(0x6A86)
        case 0xB0:
            var offset = Int(a.p1) << 8 | Int(a.p2)
            if a.p1 & 0x80 != 0 {
                guard a.p1 & 0x1F == 0x1C, let ca = cardAccess else { return sw(0x6A82) }
                selected = 0x011C
                files[0x011C] = ca
                offset = Int(a.p2)
            }
            guard let fid = selected, let file = files[fid] else { return sw(0x6986) }
            if fid != 0x011C && sm == nil { return sw(0x6982) }
            guard offset <= file.count else { return sw(0x6B00) }
            let n = min(a.ne ?? 256, file.count - offset)
            return sw(n < (a.ne ?? 0) ? 0x6282 : 0x9000, Array(file[offset..<offset + n]))
        case 0xB1:
            guard sm != nil, let fid = selected, let file = files[fid],
                  let (t, _) = try? TLV.parse(a.data), t.tag == 0x54 else { return sw(0x6A80) }
            let offset = intValue(t.value)
            let n = min((a.ne ?? 256) - 4, file.count - offset)
            return sw(0x9000, TLV.encode(0x53, Array(file[offset..<offset + max(0, n)])))
        case 0x84:
            rndIC = secureRandom(8)
            return sw(0x9000, rndIC!)
        case 0x82:
            return externalAuthenticate(a.data)
        case 0x22:
            guard let t = try? TLV.parseAll(a.data), let ref = t.first(where: { $0.tag == 0x83 })?.value.first else { return sw(0x6A80) }
            passwordRef = ref
            paceStep = 1
            return sw(0x9000)
        case 0x86:
            return generalAuthenticate(a)
        default:
            return sw(0x6D00)
        }
    }

    private func externalAuthenticate(_ data: Bytes) -> ResponseAPDU {
        guard let rndIC, data.count == 40 else { return sw(0x6700) }
        let keys = BAC.keys(for: mrzKey)
        let e = Array(data[0..<32]), m = Array(data[32..<40])
        guard retailMAC(key: keys.kMac, pad(e, blockSize: 8)) == m else { return sw(0x6300) }
        let s = BlockCipher.tdes.decryptCBC(key: keys.kEnc, e)
        guard Array(s[8..<16]) == rndIC else { return sw(0x6300) }
        let rndIFD = Array(s[0..<8]), kIFD = Array(s[16..<32])
        let kIC = secureRandom(16)
        let r = BlockCipher.tdes.encryptCBC(key: keys.kEnc, rndIC + rndIFD + kIC)
        let resp = r + retailMAC(key: keys.kMac, pad(r, blockSize: 8))
        let seed = xor(kIFD, kIC)
        sm = SecureMessaging(algorithm: .tdes, kEnc: deriveKey(seed, counter: 1, algorithm: .tdes),
                             kMac: deriveKey(seed, counter: 2, algorithm: .tdes), ssc: Array(rndIC[4..<8]) + Array(rndIFD[4..<8]))
        // transmit() already chose to send this response unprotected; later commands use SM.
        return sw(0x9000, resp)
    }

    private func generalAuthenticate(_ a: CommandAPDU) -> ResponseAPDU {
        guard case .pace(let info) = mode, let alg = info.cipher, let curve = info.curve else { return sw(0x6D00) }
        guard let (outer, _) = try? TLV.parse(a.data), outer.tag == 0x7C else { return sw(0x6A80) }
        let g = group ?? curve.group
        group = g
        let password: AccessKey = passwordRef == 1 ? .mrz(mrzKey) : .can(can)
        switch paceStep {
        case 1:
            nonce = secureRandom(16)
            let (kPi, _) = PACE.passwordKey(password, algorithm: alg)
            let z = alg.cipher.encryptCBC(key: kPi, nonce)
            paceStep = 2
            return sw(0x9000, TLV.encode(0x7C, TLV.encode(0x80, z)))
        case 2:
            guard let pk = outer.child(0x81).flatMap({ g.decode($0.value) }) else { return sw(0x6A80) }
            let k = g.makeKeyPair()
            mapKey = k
            mappedG = PACE.mapGenerator(group: g, nonce: nonce, sharedPoint: g.multiply(k.privateKey, pk))
            paceStep = 3
            return sw(0x9000, TLV.encode(0x7C, TLV.encode(0x82, g.encode(k.publicKey))))
        case 3:
            guard let pkBytes = outer.child(0x83)?.value, let pk = g.decode(pkBytes), let mg = mappedG else { return sw(0x6A80) }
            let k = g.makeKeyPair(generator: mg)
            ephKey = k
            pkIFD = pkBytes
            let shared = g.multiply(k.privateKey, pk)
            sessionKeys = (deriveKey(shared.x, counter: 1, algorithm: alg), deriveKey(shared.x, counter: 2, algorithm: alg))
            paceStep = 4
            return sw(0x9000, TLV.encode(0x7C, TLV.encode(0x84, g.encode(k.publicKey))))
        case 4:
            guard let (kEnc, kMac) = sessionKeys, let eph = ephKey else { return sw(0x6985) }
            let pkIC = g.encode(eph.publicKey)
            let expected = PACE.authenticationToken(macKey: kMac, algorithm: alg, oid: info.oid, point: pkIC)
            guard outer.child(0x85)?.value == expected else { paceStep = 0; return sw(0x6300) }
            let token = PACE.authenticationToken(macKey: kMac, algorithm: alg, oid: info.oid, point: pkIFD)
            paceStep = 0
            sm = SecureMessaging(algorithm: alg, kEnc: kEnc, kMac: kMac, ssc: Bytes(repeating: 0, count: alg.blockSize))
            return sw(0x9000, TLV.encode(0x7C, TLV.encode(0x86, token)))
        default:
            return sw(0x6985)
        }
    }
}

// MARK: - Test document

enum TestDocument {
    static let td3 = "P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<\nL898902C36UTO7408122F1204159ZE184226B<<<<<10"

    static func files(imageSize: Int = 40_000) -> [UInt16: Bytes] {
        let com = TLV.encode(0x60, TLV.encode(0x5F01, Bytes("0107".utf8)) + TLV.encode(0x5F36, Bytes("040000".utf8))
            + TLV.encode(0x5C, [0x61, 0x75, 0x6B]))
        let dg1 = TLV.encode(0x61, TLV.encode(0x5F1F, Bytes(td3.replacingOccurrences(of: "\n", with: "").utf8)))

        var jpeg: Bytes = [0xFF, 0xD8, 0xFF, 0xE0]
        jpeg += (0..<imageSize).map { UInt8(truncatingIfNeeded: $0 &* 31) }
        var fac: Bytes = [0x46, 0x41, 0x43, 0x00, 0x30, 0x31, 0x30, 0x00]
        fac += bigEndian(14 + 20 + 12 + jpeg.count, width: 4) + [0x00, 0x01]
        fac += bigEndian(20 + 12 + jpeg.count, width: 4) + [0x00, 0x00] + Bytes(repeating: 0, count: 14)
        fac += [0x01, 0x00] + bigEndian(480, width: 2) + bigEndian(640, width: 2) + Bytes(repeating: 0, count: 6)
        fac += jpeg
        let bit = TLV.encode(0x7F60, TLV.encode(0xA1, TLV.encode(0x80, [0x01, 0x01])) + TLV.encode(0x5F2E, fac))
        let dg2 = TLV.encode(0x75, TLV.encode(0x7F61, TLV.encode(0x02, [0x01]) + bit))

        let dg11 = TLV.encode(0x6B, TLV.encode(0x5C, [0x5F, 0x0E, 0x5F, 0x11]) + TLV.encode(0x5F0E, Bytes("ERIKSSON<<ANNA<MARIA".utf8))
            + TLV.encode(0x5F11, Bytes("ZENITH,UTOPIA".utf8)))

        func hashEntry(_ n: UInt8, _ d: Bytes) -> Bytes {
            TLV.encode(0x30, TLV.encode(0x02, [n]) + TLV.encode(0x04, HashAlgorithm.sha256.hash(d)))
        }
        let lds = TLV.encode(0x30, TLV.encode(0x02, [0]) + TLV.encode(0x30, TLV.encode(0x06, ASN1.encodeOID("2.16.840.1.101.3.4.2.1")))
            + TLV.encode(0x30, hashEntry(1, dg1) + hashEntry(2, dg2) + hashEntry(11, dg11)))
        let encap = TLV.encode(0x30, TLV.encode(0x06, ASN1.encodeOID("2.23.136.1.1.1")) + TLV.encode(0xA0, TLV.encode(0x04, lds)))
        let signedData = TLV.encode(0x30, TLV.encode(0x02, [3]) + TLV.encode(0x31, []) + encap + TLV.encode(0x31, []))
        let sod = TLV.encode(0x77, TLV.encode(0x30, TLV.encode(0x06, ASN1.encodeOID("1.2.840.113549.1.7.2")) + TLV.encode(0xA0, signedData)))

        return [0x011E: com, 0x0101: dg1, 0x0102: dg2, 0x010B: dg11, 0x011D: sod]
    }
}
