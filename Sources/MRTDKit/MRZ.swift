import Foundation

public enum MRZFormat: String {
    case td1 = "TD1 (ID card, 3×30)"
    case td2 = "TD2 (2×36)"
    case td3 = "TD3 (passport, 2×44)"
}

public enum MRZError: Error, LocalizedError {
    case unrecognizedFormat
    case invalidField(String)

    public var errorDescription: String? {
        switch self {
        case .unrecognizedFormat: return "Text is not a TD1, TD2 or TD3 machine readable zone"
        case .invalidField(let f): return "Invalid MRZ field: \(f)"
        }
    }
}

/// The data needed to derive BAC / PACE keys from the MRZ.
public struct MRZKey: Equatable {
    public var documentNumber: String
    /// YYMMDD
    public var dateOfBirth: String
    /// YYMMDD
    public var dateOfExpiry: String

    public init(documentNumber: String, dateOfBirth: String, dateOfExpiry: String) {
        self.documentNumber = documentNumber.uppercased().replacingOccurrences(of: " ", with: "")
        self.dateOfBirth = dateOfBirth
        self.dateOfExpiry = dateOfExpiry
    }

    public var validationError: String? {
        let docOK = documentNumber.count >= 1 && documentNumber.allSatisfy { MRZ.isMRZChar($0) }
        if !docOK { return "Document number must contain only A–Z, 0–9" }
        for (name, d) in [("Date of birth", dateOfBirth), ("Date of expiry", dateOfExpiry)] {
            guard d.count == 6, d.allSatisfy(\.isNumber),
                  let mm = Int(d.dropFirst(2).prefix(2)), let dd = Int(d.suffix(2)),
                  (1...12).contains(mm), (1...31).contains(dd)
            else { return "\(name) must be YYMMDD" }
        }
        return nil
    }

    /// "MRZ_information" from ICAO 9303 part 11: document number, birth date and expiry date,
    /// each followed by its check digit.
    public var mrzInformation: String {
        var doc = documentNumber
        while doc.count < 9 { doc += "<" }
        return doc + String(MRZ.checkDigit(doc)) + dateOfBirth + String(MRZ.checkDigit(dateOfBirth))
            + dateOfExpiry + String(MRZ.checkDigit(dateOfExpiry))
    }
}

/// What the chip should be unlocked with.
public enum AccessKey: Equatable {
    case mrz(MRZKey)
    /// Card Access Number, printed on the front of many ID cards (usually 6 digits).
    case can(String)
}

public struct MRZ: Equatable {
    public let format: MRZFormat
    public let lines: [String]
    public let documentCode: String
    public let issuingState: String
    public let documentNumber: String
    public let nationality: String
    public let dateOfBirth: String
    public let sex: String
    public let dateOfExpiry: String
    public let optionalData: String
    public let optionalData2: String
    public let surname: String
    public let givenNames: String

    public let documentNumberValid: Bool
    public let dateOfBirthValid: Bool
    public let dateOfExpiryValid: Bool
    public let compositeValid: Bool

    /// True when the check digits needed for chip access are all correct.
    public var keyFieldsValid: Bool { documentNumberValid && dateOfBirthValid && dateOfExpiryValid }
    public var allValid: Bool { keyFieldsValid && compositeValid }

    public var key: MRZKey {
        MRZKey(documentNumber: documentNumber, dateOfBirth: dateOfBirth, dateOfExpiry: dateOfExpiry)
    }

    // MARK: check digits

    public static func isMRZChar(_ c: Character) -> Bool {
        c == "<" || ("0"..."9").contains(c) || ("A"..."Z").contains(c)
    }

    static func charValue(_ c: Character) -> Int {
        if let d = c.wholeNumberValue, c.isASCII { return d }
        if let a = c.asciiValue, a >= 65, a <= 90 { return Int(a) - 55 }
        return 0
    }

    public static func checkDigit(_ s: some StringProtocol) -> Character {
        let weights = [7, 3, 1]
        let sum = s.enumerated().reduce(0) { $0 + charValue($1.element) * weights[$1.offset % 3] }
        return Character(String(sum % 10))
    }

    static func checks(_ field: some StringProtocol, _ digit: Character) -> Bool {
        // A '<' check digit is allowed for an empty optional field.
        if digit == "<" { return field.allSatisfy { $0 == "<" } }
        return checkDigit(field) == digit
    }

    // MARK: parsing

    /// Parses MRZ text. Lines may be separated by newlines; whitespace inside lines is removed.
    public init(_ text: String) throws {
        let lines = text.uppercased()
            .split(whereSeparator: \.isNewline)
            .map { $0.filter { !$0.isWhitespace } }
            .filter { !$0.isEmpty }
        try self.init(lines: lines)
    }

    public init(lines: [String]) throws {
        let lens = lines.map(\.count)
        if lens == [30, 30, 30] {
            try self.init(td1: lines)
        } else if lens == [44, 44] {
            try self.init(td23: lines, format: .td3)
        } else if lens == [36, 36] {
            try self.init(td23: lines, format: .td2)
        } else {
            throw MRZError.unrecognizedFormat
        }
    }

    private init(td1 l: [String]) throws {
        let l1 = Array(l[0]), l2 = Array(l[1])
        func s(_ a: [Character], _ r: Range<Int>) -> String { String(a[r]) }
        format = .td1
        lines = l
        documentCode = MRZ.trim(s(l1, 0..<2))
        issuingState = MRZ.trim(s(l1, 2..<5))
        var docNum = s(l1, 5..<14)
        var docCheck = l1[14]
        var opt1 = s(l1, 15..<30)
        if docCheck == "<" {
            // Document number longer than 9 characters continues in the optional data;
            // its check digit is the last character before the filler.
            let ext = opt1.prefix { $0 != "<" }
            if let last = ext.last {
                docNum += ext.dropLast()
                docCheck = last
                opt1 = String(opt1.dropFirst(ext.count))
            }
        }
        documentNumber = MRZ.trim(docNum)
        documentNumberValid = MRZ.checks(docNum, docCheck)
        optionalData = MRZ.trim(opt1)

        dateOfBirth = s(l2, 0..<6)
        dateOfBirthValid = MRZ.checks(dateOfBirth, l2[6])
        sex = MRZ.trim(s(l2, 7..<8))
        dateOfExpiry = s(l2, 8..<14)
        dateOfExpiryValid = MRZ.checks(dateOfExpiry, l2[14])
        nationality = MRZ.trim(s(l2, 15..<18))
        optionalData2 = MRZ.trim(s(l2, 18..<29))
        let composite = s(l1, 5..<30) + s(l2, 0..<7) + s(l2, 8..<15) + s(l2, 18..<29)
        compositeValid = MRZ.checks(composite, l2[29])
        (surname, givenNames) = MRZ.names(l[2])
        try validateDates()
    }

    private init(td23 l: [String], format: MRZFormat) throws {
        let l1 = Array(l[0]), l2 = Array(l[1])
        func s(_ a: [Character], _ r: Range<Int>) -> String { String(a[r]) }
        self.format = format
        lines = l
        documentCode = MRZ.trim(s(l1, 0..<2))
        issuingState = MRZ.trim(s(l1, 2..<5))
        (surname, givenNames) = MRZ.names(s(l1, 5..<l1.count))
        let last = l2.count - 1
        var docNum = s(l2, 0..<9)
        let docCheck = l2[9]
        let optEnd = format == .td3 ? 42 : 35
        var opt = s(l2, 28..<optEnd)
        if format == .td2 && docCheck == "<" {
            // Long document numbers in TD2 overflow into the optional data, like TD1.
            let ext = opt.prefix { $0 != "<" }
            if let lastChar = ext.last {
                docNum += ext.dropLast()
                opt = String(opt.dropFirst(ext.count))
                documentNumberValid = MRZ.checks(docNum, lastChar)
            } else {
                documentNumberValid = false
            }
        } else {
            documentNumberValid = MRZ.checks(docNum, docCheck)
        }
        documentNumber = MRZ.trim(docNum)
        nationality = MRZ.trim(s(l2, 10..<13))
        dateOfBirth = s(l2, 13..<19)
        dateOfBirthValid = MRZ.checks(dateOfBirth, l2[19])
        sex = MRZ.trim(s(l2, 20..<21))
        dateOfExpiry = s(l2, 21..<27)
        dateOfExpiryValid = MRZ.checks(dateOfExpiry, l2[27])
        optionalData = MRZ.trim(opt)
        optionalData2 = ""
        let composite: String
        if format == .td3 {
            composite = s(l2, 0..<10) + s(l2, 13..<20) + s(l2, 21..<43)
        } else {
            composite = s(l2, 0..<10) + s(l2, 13..<20) + s(l2, 21..<35)
        }
        compositeValid = MRZ.checks(composite, l2[last])
        try validateDates()
    }

    private func validateDates() throws {
        for d in [dateOfBirth, dateOfExpiry] where !d.allSatisfy({ $0.isNumber || $0 == "<" }) {
            throw MRZError.invalidField("date") // value omitted: errors end up in logs
        }
    }

    static func trim(_ s: String) -> String {
        s.replacingOccurrences(of: "<", with: " ").trimmingCharacters(in: .whitespaces)
    }

    static func names(_ field: String) -> (String, String) {
        let parts = field.components(separatedBy: "<<")
        let surname = trim(parts.first ?? "")
        let given = trim(parts.dropFirst().joined(separator: " ")).split(separator: " ").joined(separator: " ")
        return (surname, given)
    }
}

// MARK: - Date helpers

public enum MRZDate {
    /// Converts YYMMDD to a date, choosing the century relative to today.
    public static func date(_ yymmdd: String, isExpiry: Bool) -> DateComponents? {
        guard yymmdd.count == 6, let yy = Int(yymmdd.prefix(2)), let mm = Int(yymmdd.dropFirst(2).prefix(2)),
              let dd = Int(yymmdd.suffix(2)) else { return nil }
        let currentYY = Calendar(identifier: .gregorian).component(.year, from: Date()) % 100
        let century: Int
        if isExpiry {
            century = yy >= 70 ? 1900 : 2000
        } else {
            century = yy > currentYY ? 1900 : 2000
        }
        return DateComponents(year: century + yy, month: mm, day: dd)
    }

    public static func display(_ yymmdd: String, isExpiry: Bool) -> String {
        guard let c = date(yymmdd, isExpiry: isExpiry), let y = c.year, let m = c.month, let d = c.day else { return yymmdd }
        return String(format: "%04d-%02d-%02d", y, m, d)
    }
}
