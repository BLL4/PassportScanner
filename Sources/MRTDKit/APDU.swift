import Foundation

/// Anything that can exchange raw APDUs with a contactless chip (a PC/SC reader, a test mock…).
public protocol CardTransport: AnyObject {
    /// Sends a command APDU and returns the response including the two status bytes.
    func transmit(_ apdu: Bytes) async throws -> Bytes
}

public struct CommandAPDU: CustomStringConvertible {
    public var cla: UInt8
    public var ins: UInt8
    public var p1: UInt8
    public var p2: UInt8
    public var data: Bytes
    /// Expected response length; nil means no Le field. 256 encodes as 00.
    public var ne: Int?

    public init(cla: UInt8 = 0x00, ins: UInt8, p1: UInt8, p2: UInt8, data: Bytes = [], ne: Int? = nil) {
        self.cla = cla
        self.ins = ins
        self.p1 = p1
        self.p2 = p2
        self.data = data
        self.ne = ne
    }

    public var encoded: Bytes {
        var out: Bytes = [cla, ins, p1, p2]
        let extended = data.count > 255 || (ne ?? 0) > 256
        if extended {
            out.append(0)
            if !data.isEmpty { out += [UInt8(data.count >> 8), UInt8(data.count & 0xFF)] + data }
            if let ne { out += [UInt8((ne >> 8) & 0xFF), UInt8(ne & 0xFF)] }
        } else {
            if !data.isEmpty { out += [UInt8(data.count)] + data }
            if let ne { out.append(UInt8(ne & 0xFF)) }
        }
        return out
    }

    public var description: String { encoded.hex }
}

public struct ResponseAPDU {
    public var data: Bytes
    public var sw1: UInt8
    public var sw2: UInt8

    public init(data: Bytes, sw1: UInt8, sw2: UInt8) {
        self.data = data
        self.sw1 = sw1
        self.sw2 = sw2
    }

    public init(_ raw: Bytes) throws {
        guard raw.count >= 2 else { throw MRTDError.transport("Response shorter than status word") }
        data = Array(raw.dropLast(2))
        sw1 = raw[raw.count - 2]
        sw2 = raw[raw.count - 1]
    }

    public var sw: UInt16 { UInt16(sw1) << 8 | UInt16(sw2) }
    public var isSuccess: Bool { sw == 0x9000 }
    public var encoded: Bytes { data + [sw1, sw2] }
}

public enum MRTDError: Error, LocalizedError {
    case transport(String)
    case status(String, UInt16)
    case accessDenied(String)
    case secureMessaging(String)
    case unsupported(String)
    case malformed(String)
    case cancelled

    public var errorDescription: String? {
        switch self {
        case .transport(let s): return "Communication error: \(s)"
        case .status(let what, let sw): return "\(what) failed: \(String(format: "%04X", sw)) – \(MRTDError.describe(sw))"
        case .accessDenied(let s): return s
        case .secureMessaging(let s): return "Secure messaging error: \(s)"
        case .unsupported(let s): return "Unsupported: \(s)"
        case .malformed(let s): return "Malformed data: \(s)"
        case .cancelled: return "Cancelled"
        }
    }

    public static func describe(_ sw: UInt16) -> String {
        switch sw {
        case 0x9000: return "OK"
        case 0x6282: return "End of file reached"
        case 0x6300: return "Authentication failed"
        case 0x6700: return "Wrong length"
        case 0x6882: return "Secure messaging not supported"
        case 0x6982: return "Security status not satisfied"
        case 0x6983: return "Authentication method blocked"
        case 0x6984: return "Reference data not usable"
        case 0x6985: return "Conditions of use not satisfied"
        case 0x6987: return "Expected secure messaging objects missing"
        case 0x6988: return "Secure messaging objects incorrect"
        case 0x6A80: return "Incorrect data"
        case 0x6A82: return "File not found"
        case 0x6A86: return "Incorrect P1/P2"
        case 0x6A88: return "Referenced data not found"
        case 0x6B00: return "Wrong offset"
        case 0x6D00: return "Instruction not supported"
        case 0x6E00: return "Class not supported"
        default:
            if sw & 0xFFF0 == 0x63C0 { return "Authentication failed, \(sw & 0x0F) tries left" }
            return "Error"
        }
    }
}
