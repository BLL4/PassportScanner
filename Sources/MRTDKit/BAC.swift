import Foundation

/// Basic Access Control (ICAO 9303 part 11, section 4.3).
enum BAC {
    struct Keys {
        let kEnc: Bytes
        let kMac: Bytes
    }

    static func keys(for key: MRZKey) -> Keys {
        let seed = Array(HashAlgorithm.sha1.hash(Bytes(key.mrzInformation.utf8)).prefix(16))
        return Keys(kEnc: deriveKey(seed, counter: 1, algorithm: .tdes), kMac: deriveKey(seed, counter: 2, algorithm: .tdes))
    }

    /// Builds the EXTERNAL AUTHENTICATE data: E_IFD || M_IFD.
    static func authenticationData(keys: Keys, rndIC: Bytes, rndIFD: Bytes, kIFD: Bytes) -> Bytes {
        let s = rndIFD + rndIC + kIFD
        let eIFD = BlockCipher.tdes.encryptCBC(key: keys.kEnc, s)
        return eIFD + retailMAC(key: keys.kMac, pad(eIFD, blockSize: 8))
    }

    /// Verifies the chip's response and derives the session (secure messaging) keys.
    static func sessionKeys(keys: Keys, response: Bytes, rndIC: Bytes, rndIFD: Bytes, kIFD: Bytes) throws -> SecureMessaging {
        guard response.count == 40 else { throw MRTDError.malformed("BAC response length \(response.count)") }
        let eIC = Array(response[0..<32]), mIC = Array(response[32..<40])
        guard retailMAC(key: keys.kMac, pad(eIC, blockSize: 8)) == mIC else {
            throw MRTDError.accessDenied("BAC: chip response MAC is invalid")
        }
        let r = BlockCipher.tdes.decryptCBC(key: keys.kEnc, eIC)
        guard Array(r[0..<8]) == rndIC, Array(r[8..<16]) == rndIFD else {
            throw MRTDError.accessDenied("BAC: chip response does not match the challenge")
        }
        let kIC = Array(r[16..<32])
        let seed = xor(kIFD, kIC)
        let ssc = Array(rndIC[4..<8]) + Array(rndIFD[4..<8])
        return SecureMessaging(algorithm: .tdes, kEnc: deriveKey(seed, counter: 1, algorithm: .tdes),
                               kMac: deriveKey(seed, counter: 2, algorithm: .tdes), ssc: ssc)
    }

    static func perform(chip: Chip, key: MRZKey) async throws {
        let keys = keys(for: key)
        let rndIC = try await chip.sendExpectingSuccess(CommandAPDU(ins: 0x84, p1: 0, p2: 0, ne: 8), "GET CHALLENGE")
        guard rndIC.count == 8 else { throw MRTDError.malformed("challenge length \(rndIC.count)") }
        let rndIFD = secureRandom(8), kIFD = secureRandom(16)
        let data = authenticationData(keys: keys, rndIC: rndIC, rndIFD: rndIFD, kIFD: kIFD)
        let resp = try await chip.send(CommandAPDU(ins: 0x82, p1: 0, p2: 0, data: data, ne: 40), "EXTERNAL AUTHENTICATE")
        guard resp.isSuccess else {
            if resp.sw == 0x6300 || resp.sw == 0x6982 || resp.sw & 0xFFF0 == 0x63C0 {
                throw MRTDError.accessDenied(PassportReader.wrongKeyMessage(sw: resp.sw))
            }
            throw MRTDError.status("EXTERNAL AUTHENTICATE", resp.sw)
        }
        chip.sm = try sessionKeys(keys: keys, response: resp.data, rndIC: rndIC, rndIFD: rndIFD, kIFD: kIFD)
    }
}
