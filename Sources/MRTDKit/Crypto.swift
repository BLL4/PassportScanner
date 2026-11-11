import CommonCrypto
import CryptoKit
import Foundation

public enum CryptoError: Error, LocalizedError {
    case cipherFailed(Int32)
    case unsupported(String)

    public var errorDescription: String? {
        switch self {
        case .cipherFailed(let s): return "Cipher operation failed (\(s))"
        case .unsupported(let s): return "Unsupported algorithm: \(s)"
        }
    }
}

// MARK: - Hashes

public enum HashAlgorithm: String, CaseIterable {
    case sha1 = "SHA-1", sha224 = "SHA-224", sha256 = "SHA-256", sha384 = "SHA-384", sha512 = "SHA-512"

    public init?(oid: String) {
        switch oid {
        case "1.3.14.3.2.26": self = .sha1
        case "2.16.840.1.101.3.4.2.4": self = .sha224
        case "2.16.840.1.101.3.4.2.1": self = .sha256
        case "2.16.840.1.101.3.4.2.2": self = .sha384
        case "2.16.840.1.101.3.4.2.3": self = .sha512
        default: return nil
        }
    }

    public func hash(_ data: Bytes) -> Bytes {
        switch self {
        case .sha1: return Bytes(Insecure.SHA1.hash(data: data))
        case .sha224:
            var out = Bytes(repeating: 0, count: Int(CC_SHA224_DIGEST_LENGTH))
            _ = CC_SHA224(data, CC_LONG(data.count), &out)
            return out
        case .sha256: return Bytes(SHA256.hash(data: data))
        case .sha384: return Bytes(SHA384.hash(data: data))
        case .sha512: return Bytes(SHA512.hash(data: data))
        }
    }
}

// MARK: - Padding (ISO/IEC 9797-1 method 2)

public func pad(_ data: Bytes, blockSize: Int) -> Bytes {
    var out = data + [0x80]
    while out.count % blockSize != 0 { out.append(0) }
    return out
}

public func unpad(_ data: Bytes) -> Bytes {
    var i = data.count - 1
    while i >= 0, data[i] == 0 { i -= 1 }
    if i >= 0, data[i] == 0x80 { return Array(data[..<i]) }
    return data
}

// MARK: - Block ciphers (CommonCrypto)

enum BlockCipher {
    case des, tdes, aes

    var ccAlgorithm: CCAlgorithm {
        switch self {
        case .des: return CCAlgorithm(kCCAlgorithmDES)
        case .tdes: return CCAlgorithm(kCCAlgorithm3DES)
        case .aes: return CCAlgorithm(kCCAlgorithmAES)
        }
    }

    var blockSize: Int { self == .aes ? 16 : 8 }

    func normalizedKey(_ key: Bytes) -> Bytes {
        // CommonCrypto expects 24-byte 3DES keys; ICAO uses 2-key 3DES (K1 K2 K1).
        if self == .tdes && key.count == 16 { return key + key[0..<8] }
        return key
    }

    private func run(_ op: CCOperation, key: Bytes, iv: Bytes?, data: Bytes, ecb: Bool) -> Bytes {
        precondition(data.count % blockSize == 0, "data must be block aligned")
        let k = normalizedKey(key)
        var out = Bytes(repeating: 0, count: data.count + blockSize)
        var moved = 0
        let options = CCOptions(ecb ? kCCOptionECBMode : 0)
        let ivBytes = iv ?? Bytes(repeating: 0, count: blockSize)
        let status = CCCrypt(op, ccAlgorithm, options, k, k.count, ivBytes, data, data.count, &out, out.count, &moved)
        precondition(status == kCCSuccess, "CCCrypt failed: \(status)")
        return Array(out[0..<moved])
    }

    func encryptCBC(key: Bytes, iv: Bytes? = nil, _ data: Bytes) -> Bytes {
        run(CCOperation(kCCEncrypt), key: key, iv: iv, data: data, ecb: false)
    }

    func decryptCBC(key: Bytes, iv: Bytes? = nil, _ data: Bytes) -> Bytes {
        run(CCOperation(kCCDecrypt), key: key, iv: iv, data: data, ecb: false)
    }

    func encryptECB(key: Bytes, _ data: Bytes) -> Bytes {
        run(CCOperation(kCCEncrypt), key: key, iv: nil, data: data, ecb: true)
    }

    func decryptECB(key: Bytes, _ data: Bytes) -> Bytes {
        run(CCOperation(kCCDecrypt), key: key, iv: nil, data: data, ecb: true)
    }
}

// MARK: - MACs

/// ISO/IEC 9797-1 MAC algorithm 3 ("Retail MAC") with DES, over data that is already padded.
func retailMAC(key: Bytes, _ paddedData: Bytes) -> Bytes {
    precondition(key.count == 16 && paddedData.count % 8 == 0)
    let k1 = Array(key[0..<8]), k2 = Array(key[8..<16])
    var h = Bytes(repeating: 0, count: 8)
    var i = 0
    while i < paddedData.count {
        h = BlockCipher.des.encryptECB(key: k1, xor(h, Array(paddedData[i..<i + 8])))
        i += 8
    }
    h = BlockCipher.des.decryptECB(key: k2, h)
    return BlockCipher.des.encryptECB(key: k1, h)
}

/// AES-CMAC (RFC 4493 / NIST SP 800-38B), full 16-byte tag.
func aesCMAC(key: Bytes, _ message: Bytes) -> Bytes {
    func shiftLeft(_ b: Bytes) -> Bytes {
        var out = Bytes(repeating: 0, count: b.count)
        var carry: UInt8 = 0
        for i in stride(from: b.count - 1, through: 0, by: -1) {
            out[i] = (b[i] << 1) | carry
            carry = b[i] >> 7
        }
        return out
    }
    func subkey(_ b: Bytes) -> Bytes {
        var s = shiftLeft(b)
        if b[0] & 0x80 != 0 { s[15] ^= 0x87 }
        return s
    }
    let l = BlockCipher.aes.encryptECB(key: key, Bytes(repeating: 0, count: 16))
    let k1 = subkey(l), k2 = subkey(k1)

    let n = max(1, (message.count + 15) / 16)
    let complete = !message.isEmpty && message.count % 16 == 0
    var last: Bytes
    if complete {
        last = xor(Array(message[(n - 1) * 16..<n * 16]), k1)
    } else {
        last = xor(pad(Array(message[(n - 1) * 16..<message.count]), blockSize: 16), k2)
    }
    var x = Bytes(repeating: 0, count: 16)
    for i in 0..<(n - 1) {
        x = BlockCipher.aes.encryptECB(key: key, xor(x, Array(message[i * 16..<(i + 1) * 16])))
    }
    return BlockCipher.aes.encryptECB(key: key, xor(x, last))
}

// MARK: - Key derivation (ICAO 9303 part 11, 9.7.1)

public enum SymmetricAlgorithm: String {
    case tdes = "3DES"
    case aes128 = "AES-128"
    case aes192 = "AES-192"
    case aes256 = "AES-256"

    var cipher: BlockCipher { self == .tdes ? .tdes : .aes }
    var blockSize: Int { cipher.blockSize }
}

func adjustDESParity(_ key: Bytes) -> Bytes {
    key.map { b in
        let ones = (b >> 1).nonzeroBitCount
        return (b & 0xFE) | (ones % 2 == 0 ? 1 : 0)
    }
}

/// KDF(K, c): c = 1 for encryption keys, 2 for MAC keys, 3 for the PACE password key.
public func deriveKey(_ seed: Bytes, counter: UInt32, algorithm: SymmetricAlgorithm) -> Bytes {
    let input = seed + bigEndian(Int(counter), width: 4)
    switch algorithm {
    case .tdes: return adjustDESParity(Array(HashAlgorithm.sha1.hash(input)[0..<16]))
    case .aes128: return Array(HashAlgorithm.sha1.hash(input)[0..<16])
    case .aes192: return Array(HashAlgorithm.sha256.hash(input)[0..<24])
    case .aes256: return HashAlgorithm.sha256.hash(input)
    }
}
