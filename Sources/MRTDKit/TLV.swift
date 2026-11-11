import Foundation

public enum TLVError: Error, LocalizedError {
    case truncated
    case badLength

    public var errorDescription: String? {
        switch self {
        case .truncated: return "Malformed TLV: data truncated"
        case .badLength: return "Malformed TLV: unsupported length encoding"
        }
    }
}

/// A BER-TLV / DER element. Tags are stored with all their bytes, e.g. 0x5F1F or 0x7F61.
public struct TLV {
    public let tag: UInt32
    public let value: Bytes
    /// The complete encoding (tag + length + value) as found in the input.
    public let encoded: Bytes

    public var isConstructed: Bool {
        var first = tag
        while first > 0xFF { first >>= 8 }
        return first & 0x20 != 0
    }

    public var children: [TLV] { (try? TLV.parseAll(value)) ?? [] }

    public func child(_ tag: UInt32) -> TLV? { children.first { $0.tag == tag } }

    public func children(_ tag: UInt32) -> [TLV] { children.filter { $0.tag == tag } }

    /// Depth-first search through nested constructed elements.
    public func find(_ tag: UInt32) -> TLV? {
        if self.tag == tag { return self }
        guard isConstructed else { return nil }
        for c in children { if let f = c.find(tag) { return f } }
        return nil
    }

    public static func parse(_ bytes: Bytes, at start: Int = 0) throws -> (TLV, next: Int) {
        var i = start
        guard i < bytes.count else { throw TLVError.truncated }
        var tag = UInt32(bytes[i])
        if bytes[i] & 0x1F == 0x1F {
            repeat {
                i += 1
                guard i < bytes.count else { throw TLVError.truncated }
                tag = (tag << 8) | UInt32(bytes[i])
            } while bytes[i] & 0x80 != 0
        }
        i += 1
        guard i < bytes.count else { throw TLVError.truncated }
        var length = Int(bytes[i])
        i += 1
        if length & 0x80 != 0 {
            let n = length & 0x7F
            guard n >= 1, n <= 4 else { throw TLVError.badLength }
            guard i + n <= bytes.count else { throw TLVError.truncated }
            length = intValue(bytes[i..<i + n])
            i += n
        }
        guard i + length <= bytes.count else { throw TLVError.truncated }
        let tlv = TLV(tag: tag, value: Array(bytes[i..<i + length]), encoded: Array(bytes[start..<i + length]))
        return (tlv, i + length)
    }

    public static func parseAll(_ bytes: Bytes) throws -> [TLV] {
        var out = [TLV]()
        var i = 0
        while i < bytes.count {
            // Skip padding bytes that some chips leave at the end of files.
            if bytes[i] == 0x00 || bytes[i] == 0xFF { i += 1; continue }
            let (t, next) = try parse(bytes, at: i)
            out.append(t)
            i = next
        }
        return out
    }

    /// Returns (header length, value length) for a TLV whose beginning is in `bytes`,
    /// used to find out how large a file is after reading only its first bytes.
    public static func headerInfo(_ bytes: Bytes) -> (headerLength: Int, valueLength: Int)? {
        var i = 0
        guard bytes.count >= 2 else { return nil }
        if bytes[0] & 0x1F == 0x1F {
            repeat {
                i += 1
                guard i < bytes.count else { return nil }
            } while bytes[i] & 0x80 != 0
        }
        i += 1
        guard i < bytes.count else { return nil }
        var length = Int(bytes[i])
        i += 1
        if length & 0x80 != 0 {
            let n = length & 0x7F
            guard n >= 1, n <= 4, i + n <= bytes.count else { return nil }
            length = intValue(bytes[i..<i + n])
            i += n
        }
        return (i, length)
    }

    public static func encodeLength(_ length: Int) -> Bytes {
        switch length {
        case 0..<0x80: return [UInt8(length)]
        case 0x80...0xFF: return [0x81, UInt8(length)]
        case 0x100...0xFFFF: return [0x82, UInt8(length >> 8), UInt8(length & 0xFF)]
        default: return [0x83, UInt8(length >> 16), UInt8((length >> 8) & 0xFF), UInt8(length & 0xFF)]
        }
    }

    public static func encode(_ tag: UInt32, _ value: Bytes) -> Bytes {
        var tagBytes = Bytes()
        var t = tag
        repeat {
            tagBytes.insert(UInt8(t & 0xFF), at: 0)
            t >>= 8
        } while t != 0
        return tagBytes + encodeLength(value.count) + value
    }
}

// MARK: - ASN.1 helpers

public enum ASN1 {
    public static func decodeOID(_ bytes: Bytes) -> String {
        guard !bytes.isEmpty else { return "" }
        var parts: [UInt64] = []
        var value: UInt64 = 0
        var firstDone = false
        for b in bytes {
            value = (value << 7) | UInt64(b & 0x7F)
            if b & 0x80 == 0 {
                if !firstDone {
                    let x = min(value / 40, 2)
                    parts.append(x)
                    parts.append(value - 40 * x)
                    firstDone = true
                } else {
                    parts.append(value)
                }
                value = 0
            }
        }
        return parts.map(String.init).joined(separator: ".")
    }

    /// Content bytes of an OBJECT IDENTIFIER (without tag and length).
    public static func encodeOID(_ dotted: String) -> Bytes {
        let parts = dotted.split(separator: ".").compactMap { UInt64($0) }
        guard parts.count >= 2 else { return [] }
        var out: Bytes = []
        func base128(_ v: UInt64) -> Bytes {
            var v = v
            var tmp: Bytes = [UInt8(v & 0x7F)]
            v >>= 7
            while v > 0 {
                tmp.insert(UInt8(v & 0x7F) | 0x80, at: 0)
                v >>= 7
            }
            return tmp
        }
        out += base128(parts[0] * 40 + parts[1])
        for p in parts.dropFirst(2) { out += base128(p) }
        return out
    }

    /// Unsigned magnitude of a DER INTEGER (leading sign byte removed).
    public static func unsignedInteger(_ bytes: Bytes) -> Bytes {
        let stripped = Array(bytes.drop(while: { $0 == 0 }))
        return stripped.isEmpty ? [0] : stripped
    }

    public static func intValue(_ tlv: TLV?) -> Int? {
        guard let tlv, tlv.tag == 0x02, tlv.value.count <= 8 else { return nil }
        return MRTDKit.intValue(tlv.value)
    }

    public static func string(_ tlv: TLV) -> String {
        switch tlv.tag {
        case 0x1E: // BMPString
            var chars = [UInt16]()
            var i = 0
            while i + 1 < tlv.value.count {
                chars.append(UInt16(tlv.value[i]) << 8 | UInt16(tlv.value[i + 1]))
                i += 2
            }
            return String(utf16CodeUnits: chars, count: chars.count)
        case 0x14, 0x1A, 0x13, 0x16: // T61, Visible, Printable, IA5
            return String(decoding: tlv.value, as: UTF8.self)
        default:
            return String(data: Data(tlv.value), encoding: .utf8) ?? String(decoding: tlv.value, as: UTF8.self)
        }
    }

    /// Parses a DER-encoded UTCTime or GeneralizedTime.
    public static func date(_ tlv: TLV) -> Date? {
        let s = String(decoding: tlv.value, as: UTF8.self)
        let f = DateFormatter()
        f.locale = Locale(identifier: "en_US_POSIX")
        f.timeZone = TimeZone(identifier: "UTC")
        f.dateFormat = tlv.tag == 0x17 ? "yyMMddHHmmss'Z'" : "yyyyMMddHHmmss'Z'"
        return f.date(from: s)
    }
}
