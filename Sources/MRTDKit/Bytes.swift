import Foundation

public typealias Bytes = [UInt8]

public extension Array where Element == UInt8 {
    /// Parses a hex string; whitespace is ignored. Returns nil on malformed input.
    init?(hex: String) {
        let clean = hex.filter { !$0.isWhitespace }
        guard clean.count % 2 == 0 else { return nil }
        var out = Bytes()
        out.reserveCapacity(clean.count / 2)
        var idx = clean.startIndex
        while idx < clean.endIndex {
            let next = clean.index(idx, offsetBy: 2)
            guard let b = UInt8(clean[idx..<next], radix: 16) else { return nil }
            out.append(b)
            idx = next
        }
        self = out
    }

    var hex: String { map { String(format: "%02X", $0) }.joined() }

    var data: Data { Data(self) }
}

func xor(_ a: Bytes, _ b: Bytes) -> Bytes {
    precondition(a.count == b.count)
    return zip(a, b).map { $0 ^ $1 }
}

/// Big-endian encoding of an integer into `width` bytes.
func bigEndian(_ value: Int, width: Int) -> Bytes {
    (0..<width).map { UInt8(truncatingIfNeeded: value >> (8 * (width - 1 - $0))) }
}

/// Unsigned big-endian bytes to Int (for small values such as lengths and offsets).
func intValue(_ bytes: some Collection<UInt8>) -> Int {
    bytes.reduce(0) { ($0 << 8) | Int($1) }
}

func secureRandom(_ count: Int) -> Bytes {
    var out = Bytes(repeating: 0, count: count)
    let status = SecRandomCopyBytes(kSecRandomDefault, count, &out)
    precondition(status == errSecSuccess, "SecRandomCopyBytes failed")
    return out
}

/// Strips leading zero bytes and left-pads to `length`.
func leftPad(_ bytes: Bytes, to length: Int) -> Bytes {
    var b = Array(bytes.drop(while: { $0 == 0 }))
    if b.count < length { b = Bytes(repeating: 0, count: length - b.count) + b }
    return b
}
