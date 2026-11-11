import Foundation

/// A chip session: sends APDUs, applies secure messaging once established, and implements
/// the read-only file commands (SELECT, READ BINARY). No command that writes to the chip is ever sent.
public final class Chip {
    let transport: CardTransport
    var sm: SecureMessaging?
    var log: (String) -> Void
    /// Maximum bytes requested per READ BINARY. 0xDF keeps protected responses below 256 bytes.
    public var maxReadLength = 0xDF

    public init(transport: CardTransport, log: @escaping (String) -> Void = { _ in }) {
        self.transport = transport
        self.log = log
    }

    /// Sends a command, protecting it if secure messaging is active.
    @discardableResult
    func send(_ apdu: CommandAPDU, _ what: String) async throws -> ResponseAPDU {
        try Task.checkCancellation()
        // Read-only guard: refuse anything other than the commands needed for reading.
        let allowed: Set<UInt8> = [0xA4, 0xB0, 0xB1, 0x84, 0x82, 0x22, 0x86, 0xC0]
        guard allowed.contains(apdu.ins) else { throw MRTDError.unsupported("refusing to send INS \(String(format: "%02X", apdu.ins))") }

        var wire = apdu
        if let sm { wire = sm.protect(apdu) }
        log("→ \(what): \(Chip.redacted(apdu))\(sm == nil ? "" : "  [SM]")")
        var raw = try await transport.transmit(wire.encoded)
        var resp = try ResponseAPDU(raw)
        // 61xx: more data available (T=0 style); fetch with GET RESPONSE.
        while resp.sw1 == 0x61 && sm == nil {
            raw = try await transport.transmit([0x00, 0xC0, 0x00, 0x00, resp.sw2])
            let more = try ResponseAPDU(raw)
            resp = ResponseAPDU(data: resp.data + more.data, sw1: more.sw1, sw2: more.sw2)
        }
        if let sm {
            if resp.data.isEmpty {
                log("← \(String(format: "%04X", resp.sw)) (unprotected) \(MRTDError.describe(resp.sw))")
                self.sm = nil
                throw MRTDError.status(what, resp.sw)
            }
            resp = try sm.unprotect(resp)
        }
        // Never log response data: after unlocking it is decrypted personal data.
        log("← \(resp.data.count) bytes, \(String(format: "%04X", resp.sw))")
        return resp
    }

    /// A loggable description of a command that never contains personal or key-derived data:
    /// header and lengths only, plus the data of SELECT (file IDs) and MSE:Set AT (protocol OIDs).
    /// Authentication data is omitted on purpose: a BAC transcript would allow an offline
    /// brute-force search for the MRZ data.
    static func redacted(_ apdu: CommandAPDU) -> String {
        var s = [apdu.cla, apdu.ins, apdu.p1, apdu.p2].hex
        if !apdu.data.isEmpty {
            s += (apdu.ins == 0xA4 || apdu.ins == 0x22) ? " \(apdu.data.hex)" : " [\(apdu.data.count) bytes]"
        }
        if let ne = apdu.ne { s += " Le=\(ne)" }
        return s
    }

    func sendExpectingSuccess(_ apdu: CommandAPDU, _ what: String) async throws -> Bytes {
        let r = try await send(apdu, what)
        guard r.isSuccess || r.sw == 0x6282 else { throw MRTDError.status(what, r.sw) }
        return r.data
    }

    // MARK: file access

    public static let eMRTDApplicationID: Bytes = [0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01]

    func selectApplication() async throws {
        _ = try await sendExpectingSuccess(CommandAPDU(ins: 0xA4, p1: 0x04, p2: 0x0C, data: Chip.eMRTDApplicationID), "SELECT eMRTD application")
    }

    func selectMasterFile() async throws {
        _ = try await sendExpectingSuccess(CommandAPDU(ins: 0xA4, p1: 0x00, p2: 0x0C, data: [0x3F, 0x00]), "SELECT MF")
    }

    /// Reads a complete transparent elementary file identified by its 2-byte file ID.
    public func readFile(_ fid: [UInt8], name: String, progress: ((Double) -> Void)? = nil) async throws -> Bytes {
        _ = try await sendExpectingSuccess(CommandAPDU(ins: 0xA4, p1: 0x02, p2: 0x0C, data: fid), "SELECT \(name)")
        return try await readSelected(name: name, progress: progress)
    }

    /// Reads a file by short file identifier without selecting it first (used for EF.CardAccess).
    public func readFile(sfi: UInt8, name: String) async throws -> Bytes {
        let head = try await sendExpectingSuccess(CommandAPDU(ins: 0xB0, p1: 0x80 | sfi, p2: 0x00, ne: 4), "READ \(name)")
        return try await readRest(head: head, name: name, progress: nil)
    }

    private func readSelected(name: String, progress: ((Double) -> Void)?) async throws -> Bytes {
        let head = try await readBinary(offset: 0, length: 4, name: name)
        return try await readRest(head: head, name: name, progress: progress)
    }

    private func readRest(head: Bytes, name: String, progress: ((Double) -> Void)?) async throws -> Bytes {
        var head = head
        if TLV.headerInfo(head) == nil && head.count >= 4 {
            // Long tag or length encoding: the header did not fit in the first 4 bytes.
            head += try await readBinary(offset: head.count, length: 4, name: name)
        }
        guard let (hl, vl) = TLV.headerInfo(head) else { throw MRTDError.malformed("\(name) does not start with a TLV header") }
        let total = hl + vl
        var data = Array(head.prefix(total))
        var chunk = maxReadLength
        while data.count < total {
            let want = min(chunk, total - data.count)
            do {
                let part = try await readBinary(offset: data.count, length: want, name: name)
                guard !part.isEmpty else { throw MRTDError.malformed("\(name): chip returned no data at offset \(data.count)") }
                data += part.prefix(total - data.count)
                progress?(Double(data.count) / Double(total))
            } catch MRTDError.status(_, let sw) where (sw == 0x6700 || sw & 0xFF00 == 0x6C00) && chunk > 0x20 && sm != nil {
                // Some readers/chips cannot handle the response size; retry with smaller blocks.
                chunk /= 2
                log("Reducing read size to \(chunk) bytes")
            }
        }
        return data
    }

    func readBinary(offset: Int, length: Int, name: String) async throws -> Bytes {
        if offset <= 0x7FFF {
            return try await sendExpectingSuccess(
                CommandAPDU(ins: 0xB0, p1: UInt8(offset >> 8), p2: UInt8(offset & 0xFF), ne: length), "READ \(name) @\(offset)")
        }
        // Offsets above 32767 need READ BINARY with odd INS and an offset data object.
        var off = bigEndian(offset, width: 3)
        if off[0] == 0 { off.removeFirst() }
        // Le covers the whole response including the DO53 header, so ask for a little less data.
        let resp = try await sendExpectingSuccess(
            CommandAPDU(ins: 0xB1, p1: 0, p2: 0, data: TLV.encode(0x54, off), ne: min(length, maxReadLength - 4) + 4),
            "READ \(name) @\(offset)")
        guard let (t, _) = try? TLV.parse(resp), t.tag == 0x53 else { throw MRTDError.malformed("READ BINARY (B1) response") }
        return t.value
    }
}
