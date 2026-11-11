import Foundation

/// A US / Canadian driver's license or ID card decoded from its PDF417 barcode (AAMVA DL/ID card
/// design standard). Unlike a passport chip the barcode is not signed, so the data cannot be verified.
public struct DriverLicense: Equatable {
    public var documentType: String          // "DL" or "ID"
    public var issuerID: String              // 6-digit IIN of the issuing jurisdiction
    public var aamvaVersion: Int
    /// All data elements, keyed by their 3-letter AAMVA code.
    public var elements: [String: String]
    /// Element codes in the order they appear in the barcode.
    public var order: [String]

    public func value(_ code: String) -> String? {
        guard let v = elements[code]?.trimmingCharacters(in: .whitespaces), !v.isEmpty, v.uppercased() != "NONE", v != "unavl" else { return nil }
        return v
    }

    // MARK: common fields

    public var familyName: String? { value("DCS") ?? value("DAB") ?? fullNameParts?.family }
    public var givenNames: String? {
        if let first = value("DAC") { return [first, value("DAD")].compactMap { $0 }.joined(separator: " ") }
        if let dct = value("DCT") { return dct.replacingOccurrences(of: ",", with: " ") } // AAMVA 2003–2009
        return fullNameParts?.given
    }
    public var suffix: String? { value("DCU") }
    private var fullNameParts: (family: String, given: String)? {
        // AAMVA 2000: DAA "FAMILY,GIVEN,MIDDLE"
        guard let full = value("DAA") else { return nil }
        let p = full.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
        return (p.first ?? full, p.dropFirst().joined(separator: " "))
    }

    public var licenseNumber: String? { value("DAQ") }
    public var dateOfBirth: DateComponents? { date("DBB") }
    public var dateOfExpiry: DateComponents? { date("DBA") }
    public var dateOfIssue: DateComponents? { date("DBD") }
    public var sex: String? {
        switch value("DBC") {
        case "1", "M": return "M"
        case "2", "F": return "F"
        case "9", "X": return "X"
        default: return value("DBC")
        }
    }
    public var address: String? {
        let street = [value("DAG"), value("DAH")].compactMap { $0 }.joined(separator: ", ")
        let region = [value("DAJ"), displayValue("DAK")].compactMap { $0 }.joined(separator: " ")
        let cityLine = [value("DAI"), region.isEmpty ? nil : region].compactMap { $0 }.joined(separator: ", ")
        let all = [street, cityLine].filter { !$0.isEmpty }.joined(separator: "\n")
        return all.isEmpty ? nil : all
    }
    public var state: String? { value("DAJ") }
    public var country: String? { value("DCG") }
    public var isRealIDCompliant: Bool? {
        guard let c = value("DDA") else { return nil }
        return c == "F"
    }
    public var isExpired: Bool {
        guard let c = dateOfExpiry, let d = Calendar(identifier: .gregorian).date(from: c) else { return false }
        return d < Date()
    }

    /// Dates are MMDDCCYY in US barcodes and CCYYMMDD in Canadian ones.
    public func date(_ code: String) -> DateComponents? {
        guard let v = value(code), v.count == 8, v.allSatisfy(\.isNumber) else { return nil }
        let a = Int(v.prefix(4))!, b = Int(v.suffix(4))!
        let canadian = country == "CAN" || (a > 1300 && b % 100 <= 31 && b / 100 <= 12 && !(a / 100 <= 12 && a % 100 <= 31))
        if canadian { return DateComponents(year: a, month: b / 100, day: b % 100) }
        return DateComponents(year: b, month: a / 100, day: a % 100)
    }

    static let dateCodes: Set<String> = ["DBA", "DBB", "DBD", "DDB", "DDC", "DDH", "DDI", "DDJ"]
    /// Truncation flags and similar codes that are not useful to show.
    static let hiddenCodes: Set<String> = ["DDE", "DDF", "DDG"]

    /// The element value formatted for display, or nil if it should not be shown.
    public func displayValue(_ code: String) -> String? {
        guard !DriverLicense.hiddenCodes.contains(code), let v = value(code) else { return nil }
        if DriverLicense.dateCodes.contains(code) { return DriverLicense.format(date(code)) ?? v }
        switch code {
        case "DBC": return sex
        case "DDA": return v == "F" ? "REAL ID compliant" : v == "N" ? "Not REAL ID compliant" : v
        case "DDK", "DDL", "DDD": return v == "1" ? "Yes" : v == "0" ? "No" : v
        case "DAU":
            // "069 IN" → 5'9"; "175 CM" stays.
            let digits = v.prefix { $0.isNumber }
            if v.uppercased().hasSuffix("IN"), let inches = Int(digits) { return "\(inches / 12)′\(inches % 12)″ (\(inches) in)" }
            return v
        case "DAK":
            let z = v.trimmingCharacters(in: .whitespaces)
            if z.count >= 9, z.allSatisfy(\.isNumber) {
                let plus4 = z.dropFirst(5).prefix(4)
                return plus4 == "0000" ? String(z.prefix(5)) : "\(z.prefix(5))-\(plus4)"
            }
            return z
        default: return v
        }
    }

    public static func format(_ c: DateComponents?) -> String? {
        guard let c, let y = c.year, let m = c.month, let d = c.day else { return nil }
        return String(format: "%04d-%02d-%02d", y, m, d)
    }

    /// Human-readable labels for the most common element codes, in display order.
    public static let labels: [(String, String)] = [
        ("DAQ", "License / ID number"), ("DCS", "Family name"), ("DAC", "First name"), ("DAD", "Middle name(s)"),
        ("DCU", "Suffix"), ("DBB", "Date of birth"), ("DBC", "Sex"), ("DBD", "Issue date"), ("DBA", "Expiry date"),
        ("DAG", "Street"), ("DAH", "Street 2"), ("DAI", "City"), ("DAJ", "State / province"), ("DAK", "Postal code"),
        ("DCG", "Country"), ("DCA", "Vehicle class"), ("DCB", "Restrictions"), ("DCD", "Endorsements"),
        ("DAU", "Height"), ("DAW", "Weight (lb)"), ("DAY", "Eye color"), ("DAZ", "Hair color"), ("DCL", "Race / ethnicity"),
        ("DDA", "Compliance type"), ("DDB", "Card revision date"), ("DDK", "Organ donor"), ("DDL", "Veteran"),
        ("DCF", "Document discriminator"), ("DCK", "Inventory control number"), ("DDC", "Hazmat endorsement expiry"),
        ("DDD", "Limited duration document"), ("DDH", "Under 18 until"), ("DDI", "Under 19 until"), ("DDJ", "Under 21 until"),
        ("DBN", "Alias family name"), ("DBG", "Alias given name"), ("DBS", "Alias suffix"),
        ("DAA", "Full name"), ("DAB", "Family name"), ("DCT", "Given names"),
    ]

    public static func label(_ code: String) -> String {
        labels.first { $0.0 == code }?.1 ?? code
    }

    // MARK: parsing

    public enum ParseError: Error, LocalizedError {
        case notAAMVA
        public var errorDescription: String? { "The barcode is not an AAMVA driver's license / ID barcode" }
    }

    public init(barcode text: String) throws {
        // Header: "@" LF RS CR, then "ANSI " (or "AAMVA"), IIN(6), version(2), [jurisdiction version(2)], entries(2).
        guard let ansi = text.range(of: "ANSI ") ?? text.range(of: "AAMVA"), text.distance(from: text.startIndex, to: ansi.lowerBound) < 10 else {
            throw ParseError.notAAMVA
        }
        let header = Array(text[ansi.upperBound...].prefix(40))
        issuerID = String(header.prefix(6))
        aamvaVersion = Int(String(header.dropFirst(6).prefix(2))) ?? 0

        // Locate the DL / ID subfile: the designator gives its type, then the subfile itself starts with that type.
        let designators = String(header.dropFirst(aamvaVersion >= 2 ? 12 : 10))
        var type = designators.hasPrefix("ID") ? "ID" : "DL"
        if !designators.hasPrefix("DL") && !designators.hasPrefix("ID"), text.contains("IDDAQ") || text.contains("IDDCS") { type = "ID" }
        documentType = type

        let body = String(text[ansi.upperBound...])
        var start: String.Index?
        // The subfile begins with its type immediately followed by the first element code (e.g. "DLDAQ").
        var search = body.startIndex
        while let r = body.range(of: type, range: search..<body.endIndex) {
            let after = body[r.upperBound...].prefix(3)
            if after.count == 3, after.allSatisfy({ $0.isUppercase && $0.isLetter }), after.first == "D" || after.first == "Z" {
                start = r.upperBound
                break
            }
            search = r.upperBound
        }
        guard let start else { throw ParseError.notAAMVA }

        var elements: [String: String] = [:]
        var order: [String] = []
        // isNewline also matches "\r\n", which Swift treats as a single Character.
        for raw in body[start...].split(whereSeparator: { $0.isNewline || $0 == "\u{1E}" }) {
            var line = Substring(raw.trimmingCharacters(in: .controlCharacters))
            // A jurisdiction subfile starts with its 2-letter type glued to its first element, e.g. "ZVZVA01".
            if line.count >= 5, line.first == "Z", line.prefix(2) == line.dropFirst(2).prefix(2) { line = line.dropFirst(2) }
            guard line.count >= 3 else { continue }
            let code = String(line.prefix(3))
            guard code.allSatisfy({ $0.isLetter && $0.isUppercase }), elements[code] == nil else { continue }
            elements[code] = line.dropFirst(3).trimmingCharacters(in: .whitespaces)
            order.append(code)
        }
        guard elements["DAQ"] != nil || elements["DCS"] != nil || elements["DAA"] != nil else { throw ParseError.notAAMVA }
        self.elements = elements
        self.order = order
    }
}
