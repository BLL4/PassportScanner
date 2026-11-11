import Foundation

/// ICAO 9303 part 11 secure messaging (section 9.8) for 3DES (BAC, PACE-3DES) and AES (PACE-AES).
public final class SecureMessaging {
    public let algorithm: SymmetricAlgorithm
    let kEnc: Bytes
    let kMac: Bytes
    public private(set) var ssc: Bytes

    public init(algorithm: SymmetricAlgorithm, kEnc: Bytes, kMac: Bytes, ssc: Bytes) {
        self.algorithm = algorithm
        self.kEnc = kEnc
        self.kMac = kMac
        self.ssc = ssc
    }

    var blockSize: Int { algorithm.blockSize }

    func incrementSSC() {
        for i in stride(from: ssc.count - 1, through: 0, by: -1) {
            ssc[i] &+= 1
            if ssc[i] != 0 { break }
        }
    }

    private var iv: Bytes {
        // AES: IV = E(KSenc, SSC); 3DES: zero IV.
        algorithm == .tdes ? Bytes(repeating: 0, count: 8) : BlockCipher.aes.encryptECB(key: kEnc, ssc)
    }

    func encrypt(_ data: Bytes) -> Bytes {
        algorithm.cipher.encryptCBC(key: kEnc, iv: iv, pad(data, blockSize: blockSize))
    }

    func decrypt(_ data: Bytes) -> Bytes {
        unpad(algorithm.cipher.decryptCBC(key: kEnc, iv: iv, data))
    }

    /// MAC over SSC || data, padded; 8 bytes.
    func mac(_ data: Bytes) -> Bytes {
        let n = pad(ssc + data, blockSize: blockSize)
        if algorithm == .tdes { return retailMAC(key: kMac, n) }
        return Array(aesCMAC(key: kMac, n).prefix(8))
    }

    public func protect(_ apdu: CommandAPDU) -> CommandAPDU {
        incrementSSC()
        let cla = apdu.cla | 0x0C
        let header = pad([cla, apdu.ins, apdu.p1, apdu.p2], blockSize: blockSize)
        var do87 = Bytes()
        if !apdu.data.isEmpty {
            let enc = encrypt(apdu.data)
            // Odd INS (e.g. READ BINARY B1) carries BER-TLV data in DO85 without the padding indicator.
            do87 = apdu.ins & 1 == 1 ? TLV.encode(0x85, enc) : TLV.encode(0x87, [0x01] + enc)
        }
        var do97 = Bytes()
        if let ne = apdu.ne {
            do97 = ne > 256 ? [0x97, 0x02, UInt8((ne >> 8) & 0xFF), UInt8(ne & 0xFF)] : [0x97, 0x01, UInt8(ne & 0xFF)]
        }
        let cc = mac(header + do87 + do97)
        let body = do87 + do97 + [0x8E, 0x08] + cc
        return CommandAPDU(cla: cla, ins: apdu.ins, p1: apdu.p1, p2: apdu.p2, data: body, ne: (apdu.ne ?? 0) > 256 ? 65536 : 256)
    }

    public func unprotect(_ response: ResponseAPDU) throws -> ResponseAPDU {
        incrementSSC()
        guard !response.data.isEmpty else {
            // An unprotected error status means the chip has aborted secure messaging.
            throw MRTDError.status("Secure messaging", response.sw)
        }
        let objects = try TLV.parseAll(response.data)
        var macInput = Bytes()
        var plain = Bytes()
        var sw: (UInt8, UInt8)?
        var cc: Bytes?
        for o in objects {
            switch o.tag {
            case 0x87:
                macInput += o.encoded
                guard o.value.first == 0x01 else { throw MRTDError.secureMessaging("unknown padding indicator") }
                plain = decrypt(Array(o.value.dropFirst()))
            case 0x85:
                macInput += o.encoded
                plain = algorithm.cipher.decryptCBC(key: kEnc, iv: iv, o.value)
                plain = unpad(plain)
            case 0x81:
                macInput += o.encoded
                plain = o.value
            case 0x99:
                macInput += o.encoded
                guard o.value.count == 2 else { throw MRTDError.secureMessaging("bad DO99") }
                sw = (o.value[0], o.value[1])
            case 0x8E:
                cc = o.value
            default:
                break
            }
        }
        guard let cc else { throw MRTDError.secureMessaging("response has no MAC") }
        guard cc == mac(macInput) else { throw MRTDError.secureMessaging("response MAC is invalid") }
        let (sw1, sw2) = sw ?? (response.sw1, response.sw2)
        return ResponseAPDU(data: plain, sw1: sw1, sw2: sw2)
    }
}
