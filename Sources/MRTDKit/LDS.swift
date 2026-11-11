import Foundation

/// Elementary files of the eMRTD application (LDS 1).
public enum DataGroupID: Int, CaseIterable, Comparable, Codable {
    case com = 0x1E, sod = 0x1D
    case dg1 = 1, dg2, dg3, dg4, dg5, dg6, dg7, dg8, dg9, dg10, dg11, dg12, dg13, dg14, dg15, dg16

    public var fileID: [UInt8] { [0x01, UInt8(rawValue)] }

    /// Tag of the file's outer TLV, as listed in EF.COM.
    public var tag: UInt8 {
        switch self {
        case .com: return 0x60
        case .sod: return 0x77
        case .dg1: return 0x61
        case .dg2: return 0x75
        case .dg3: return 0x63
        case .dg4: return 0x76
        case .dg5: return 0x65
        case .dg6: return 0x66
        case .dg7: return 0x67
        case .dg8: return 0x68
        case .dg9: return 0x69
        case .dg10: return 0x6A
        case .dg11: return 0x6B
        case .dg12: return 0x6C
        case .dg13: return 0x6D
        case .dg14: return 0x6E
        case .dg15: return 0x6F
        case .dg16: return 0x70
        }
    }

    public init?(tag: UInt8) {
        guard let v = DataGroupID.allCases.first(where: { $0.tag == tag }) else { return nil }
        self = v
    }

    public var name: String {
        switch self {
        case .com: return "EF.COM"
        case .sod: return "EF.SOD"
        default: return "DG\(rawValue)"
        }
    }

    public var title: String {
        switch self {
        case .com: return "Common data"
        case .sod: return "Document security object"
        case .dg1: return "MRZ"
        case .dg2: return "Face image"
        case .dg3: return "Fingerprints"
        case .dg4: return "Iris"
        case .dg5: return "Portrait"
        case .dg7: return "Signature image"
        case .dg11: return "Additional personal details"
        case .dg12: return "Additional document details"
        case .dg13: return "Optional details"
        case .dg14: return "Security options"
        case .dg15: return "Active authentication public key"
        case .dg16: return "Persons to notify"
        default: return "Data group"
        }
    }

    /// DG3/DG4 are protected by Extended Access Control and cannot be read with BAC/PACE alone.
    public var requiresEAC: Bool { self == .dg3 || self == .dg4 }

    public static func < (a: DataGroupID, b: DataGroupID) -> Bool {
        func order(_ d: DataGroupID) -> Int { d == .com ? -1 : d == .sod ? 100 : d.rawValue }
        return order(a) < order(b)
    }
}

public struct EFCOM {
    public let ldsVersion: String?
    public let unicodeVersion: String?
    public let dataGroups: [DataGroupID]

    public init(_ bytes: Bytes) throws {
        let (t, _) = try TLV.parse(bytes)
        guard t.tag == 0x60 else { throw MRTDError.malformed("EF.COM tag") }
        ldsVersion = t.child(0x5F01).map { String(decoding: $0.value, as: UTF8.self) }
        unicodeVersion = t.child(0x5F36).map { String(decoding: $0.value, as: UTF8.self) }
        dataGroups = (t.child(0x5C)?.value ?? []).compactMap(DataGroupID.init(tag:))
    }
}

public enum DG1 {
    public static func parse(_ bytes: Bytes) throws -> MRZ {
        let (t, _) = try TLV.parse(bytes)
        guard t.tag == 0x61, let mrzTLV = t.child(0x5F1F) else { throw MRTDError.malformed("DG1") }
        let text = String(decoding: mrzTLV.value, as: UTF8.self)
        let n = text.count
        let lineLength = n == 90 ? 30 : n == 72 ? 36 : 44
        var lines = [String]()
        var s = Substring(text)
        while !s.isEmpty {
            lines.append(String(s.prefix(lineLength)))
            s = s.dropFirst(lineLength)
        }
        return try MRZ(lines: lines)
    }
}

public struct FaceImage {
    public enum Format: String { case jpeg = "JPEG", jpeg2000 = "JPEG 2000", unknown = "Unknown" }
    public let data: Bytes
    public let format: Format
    public let width: Int?
    public let height: Int?
}

public enum DG2 {
    /// Extracts the first face image from DG2 (ISO/IEC 19794-5 inside a CBEFF structure).
    public static func parse(_ bytes: Bytes) throws -> FaceImage {
        let (t, _) = try TLV.parse(bytes)
        guard t.tag == 0x75 else { throw MRTDError.malformed("DG2 tag") }
        let block = t.find(0x5F2E) ?? t.find(0x7F2E)
        guard let bdb = block?.value else { throw MRTDError.malformed("DG2 has no biometric data block") }

        var width: Int?, height: Int?
        var imageStart: Int?
        // ISO 19794-5: "FAC\0", version, record length(4), count(2), then facial record.
        if bdb.count > 46, Array(bdb[0..<4]) == [0x46, 0x41, 0x43, 0x00] {
            let recordStart = 14
            let featurePoints = intValue(bdb[recordStart + 4..<recordStart + 6])
            let imageInfo = recordStart + 20 + featurePoints * 8
            if imageInfo + 12 <= bdb.count {
                width = intValue(bdb[imageInfo + 2..<imageInfo + 4])
                height = intValue(bdb[imageInfo + 4..<imageInfo + 6])
                imageStart = imageInfo + 12
            }
        }
        // Fall back to searching for an image signature.
        let signatures: [(Bytes, FaceImage.Format)] = [
            ([0xFF, 0xD8, 0xFF], .jpeg),
            ([0x00, 0x00, 0x00, 0x0C, 0x6A, 0x50, 0x20, 0x20], .jpeg2000),
            ([0xFF, 0x4F, 0xFF, 0x51], .jpeg2000),
        ]
        func format(at i: Int) -> FaceImage.Format? {
            signatures.first { sig in i + sig.0.count <= bdb.count && Array(bdb[i..<i + sig.0.count]) == sig.0 }?.1
        }
        if let start = imageStart, let f = format(at: start) {
            return FaceImage(data: Array(bdb[start...]), format: f, width: width, height: height)
        }
        for i in 0..<bdb.count {
            if let f = format(at: i) { return FaceImage(data: Array(bdb[i...]), format: f, width: width, height: height) }
        }
        throw MRTDError.malformed("DG2 contains no JPEG / JPEG 2000 image")
    }
}

/// Image from DG7 (displayed signature) — same idea as DG2 but without the biometric header.
public enum DG7 {
    public static func parse(_ bytes: Bytes) throws -> FaceImage? {
        let (t, _) = try TLV.parse(bytes)
        guard let img = t.find(0x5F43)?.value else { return nil }
        if img.starts(with: [0xFF, 0xD8]) { return FaceImage(data: img, format: .jpeg, width: nil, height: nil) }
        return FaceImage(data: img, format: .jpeg2000, width: nil, height: nil)
    }
}

/// Text fields from DG11 / DG12 / DG16 in a stable display order.
public struct LabeledFields: Equatable {
    public var items: [(label: String, value: String)]

    public static func == (a: LabeledFields, b: LabeledFields) -> Bool {
        a.items.map(\.label) == b.items.map(\.label) && a.items.map(\.value) == b.items.map(\.value)
    }
}

public enum DG11 {
    static let labels: [(UInt32, String)] = [
        (0x5F0E, "Full name"), (0x5F0F, "Other names"), (0x5F10, "Personal number"), (0x5F2B, "Full date of birth"),
        (0x5F11, "Place of birth"), (0x5F42, "Address"), (0x5F12, "Telephone"), (0x5F13, "Profession"), (0x5F14, "Title"),
        (0x5F15, "Personal summary"), (0x5F17, "Other travel document numbers"), (0x5F18, "Custody information"),
    ]

    public static func parse(_ bytes: Bytes) throws -> LabeledFields {
        let (t, _) = try TLV.parse(bytes)
        guard t.tag == 0x6B else { throw MRTDError.malformed("DG11 tag") }
        return LabeledFields(items: collect(t, labels: labels))
    }

    static func collect(_ t: TLV, labels: [(UInt32, String)]) -> [(label: String, value: String)] {
        var out: [(String, String)] = []
        func walk(_ node: TLV) {
            for c in node.children {
                if let label = labels.first(where: { $0.0 == c.tag })?.1 {
                    var v = String(decoding: c.value, as: UTF8.self)
                    if c.tag == 0x5F0E || c.tag == 0x5F0F {
                        // Names use the MRZ convention SURNAME<<GIVEN<NAMES.
                        v = v.replacingOccurrences(of: "<<", with: ", ").replacingOccurrences(of: "<", with: " ")
                    } else {
                        v = v.replacingOccurrences(of: "<", with: " ")
                    }
                    if c.tag == 0x5F2B || c.tag == 0x5F26 { v = formatDate(c.value) }
                    let trimmed = v.trimmingCharacters(in: .whitespacesAndNewlines)
                    if !trimmed.isEmpty { out.append((label, trimmed)) }
                } else if c.tag == 0xA0 || c.isConstructed {
                    walk(c)
                }
            }
        }
        walk(t)
        return out
    }

    static func formatDate(_ v: Bytes) -> String {
        // Dates are YYYYMMDD in ASCII, or 4 bytes BCD in some older chips.
        var s = String(decoding: v, as: UTF8.self)
        if v.count == 4 { s = v.map { String(format: "%02X", $0) }.joined() }
        guard s.count == 8, s.allSatisfy(\.isNumber) else { return s }
        return "\(s.prefix(4))-\(s.dropFirst(4).prefix(2))-\(s.suffix(2))"
    }
}

public enum DG12 {
    static let labels: [(UInt32, String)] = [
        (0x5F19, "Issuing authority"), (0x5F26, "Date of issue"), (0x5F1A, "Other persons"), (0x5F1B, "Endorsements / observations"),
        (0x5F1C, "Tax / exit requirements"), (0x5F55, "Personalization date/time"), (0x5F56, "Personalization system serial"),
    ]

    public static func parse(_ bytes: Bytes) throws -> LabeledFields {
        let (t, _) = try TLV.parse(bytes)
        guard t.tag == 0x6C else { throw MRTDError.malformed("DG12 tag") }
        return LabeledFields(items: DG11.collect(t, labels: labels))
    }
}
