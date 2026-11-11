import Foundation

/// Trusted Country Signing CA certificates, used to check that a Document Signer certificate
/// was issued by the document's country (the last step of passive authentication).
///
/// Sources: CSCA master lists (CMS SignedData `.ml`, e.g. from the German BSI), the ICAO PKD
/// LDIF download, or individual certificates (DER / PEM). The master list's own signature is not
/// checked: trust comes from where the file was downloaded.
public final class CSCAStore {
    public private(set) var certificates: [Certificate] = []

    public init(certificates: [Certificate] = []) {
        add(certificates)
    }

    /// Adds certificates, skipping duplicates. Returns how many were new.
    @discardableResult
    public func add(_ certs: [Certificate]) -> Int {
        var known = Set(certificates.map(\.der))
        var added = 0
        for c in certs where !known.contains(c.der) {
            certificates.append(c)
            known.insert(c.der)
            added += 1
        }
        return added
    }

    public var countries: [String] {
        Array(Set(certificates.compactMap { c in c.subject.first { $0.0 == "C" }?.1.uppercased() })).sorted()
    }

    // MARK: verification

    /// Finds the CSCA that signed `dsc` and verifies the signature.
    public func verify(dsc: Certificate) -> (PassiveAuthResult.Status, Certificate?) {
        if certificates.isEmpty { return (.notChecked("no CSCA certificates loaded"), nil) }
        var candidates = certificates.filter { $0.subjectDER == dsc.issuerDER }
        if let aki = dsc.authorityKeyIdentifier {
            // Prefer the key named by the authority key identifier (countries roll over CSCA keys).
            let byKey = certificates.filter { $0.subjectKeyIdentifier == aki }
            candidates = byKey + candidates.filter { c in !byKey.contains { $0.der == c.der } }
        }
        let country = dsc.issuer.first { $0.0 == "C" }?.1 ?? "?"
        guard !candidates.isEmpty else {
            return (.notChecked("no CSCA certificate for issuer \(dsc.issuerDescription) (country \(country)) in the loaded list"), nil)
        }
        var lastFailure = ""
        for csca in candidates {
            switch dsc.isSigned(by: csca) {
            case .valid: return (.valid, csca)
            case .invalid(let why): lastFailure = why
            case .notChecked(let why): lastFailure = why
            }
        }
        if let aki = dsc.authorityKeyIdentifier, !certificates.contains(where: { $0.subjectKeyIdentifier == aki }) {
            // The CSCA name matches but the specific key that signed is not in the list (e.g. an older key).
            return (.notChecked("the issuing CSCA key (\(aki.hex.prefix(16))…) of \(country) is not in the loaded list"), nil)
        }
        return (.invalid("the Document Signer certificate is not signed by any matching CSCA (\(lastFailure))"), nil)
    }

    // MARK: loading

    /// Extracts certificates from a master list, LDIF, PEM or DER file.
    public static func certificates(fromFile bytes: Bytes) -> [Certificate] {
        if let text = String(bytes: bytes.prefix(200_000_000), encoding: .utf8) ?? String(bytes: bytes, encoding: .isoLatin1) {
            if text.contains("-----BEGIN CERTIFICATE-----") { return pem(text) }
            if text.hasPrefix("dn:") || text.contains("\ndn:") || text.hasPrefix("version:") { return ldif(text) }
        }
        return der(bytes)
    }

    static func pem(_ text: String) -> [Certificate] {
        var out = [Certificate]()
        var rest = Substring(text)
        while let start = rest.range(of: "-----BEGIN CERTIFICATE-----"), let end = rest.range(of: "-----END CERTIFICATE-----", range: start.upperBound..<rest.endIndex) {
            let b64 = rest[start.upperBound..<end.lowerBound].filter { !$0.isWhitespace }
            if let d = Data(base64Encoded: String(b64)), let c = try? Certificate(der: Bytes(d)) { out.append(c) }
            rest = rest[end.upperBound...]
        }
        return out
    }

    /// ICAO PKD LDIF: master lists in `pkdMasterListContent`, certificates in `*Certificate;binary`.
    static func ldif(_ text: String) -> [Certificate] {
        var lines: [String] = []
        for raw in text.split(omittingEmptySubsequences: false, whereSeparator: \.isNewline) {
            if raw.hasPrefix(" "), !lines.isEmpty { lines[lines.count - 1] += raw.dropFirst() } else { lines.append(String(raw)) }
        }
        var out = [Certificate]()
        for line in lines {
            guard let r = line.range(of: ":: ") else { continue }
            let attr = line[..<r.lowerBound].lowercased()
            guard attr == "pkdmasterlistcontent" || attr.hasSuffix("certificate;binary"),
                  let d = Data(base64Encoded: String(line[r.upperBound...])) else { continue }
            out += der(Bytes(d))
        }
        return out
    }

    /// A single DER certificate, a CMS master list, or anything else containing certificates.
    static func der(_ bytes: Bytes) -> [Certificate] {
        if let c = try? Certificate(der: bytes), c.der.count == bytes.count { return [c] }
        if let list = masterList(bytes) { return list }
        return scan(bytes)
    }

    /// CscaMasterList ::= SEQUENCE { version INTEGER, certList SET OF Certificate } inside CMS SignedData.
    static func masterList(_ bytes: Bytes) -> [Certificate]? {
        guard let (ci, _) = try? TLV.parse(bytes), ci.tag == 0x30,
              let sd = ci.child(0xA0)?.child(0x30),
              let encap = sd.children.first(where: { $0.tag == 0x30 && $0.child(0x06) != nil }),
              let content = encap.child(0xA0)?.child(0x04)?.value,
              let (list, _) = try? TLV.parse(content), let set = list.child(0x31) else { return nil }
        return set.children.compactMap { try? Certificate(der: $0.encoded) }
    }

    /// Fallback for unusual encodings (e.g. indefinite lengths): look for embedded certificates.
    static func scan(_ bytes: Bytes) -> [Certificate] {
        var out = [Certificate]()
        var i = 0
        while i + 8 < bytes.count {
            if bytes[i] == 0x30, bytes[i + 1] == 0x82, bytes[i + 4] == 0x30, bytes[i + 5] == 0x82 {
                let len = 4 + intValue(bytes[i + 2..<i + 4])
                if i + len <= bytes.count, let c = try? Certificate(der: Array(bytes[i..<i + len])), c.der.count == len {
                    out.append(c)
                    i += len
                    continue
                }
            }
            i += 1
        }
        // Keep CA certificates only (master lists also carry the list signer's own certificate).
        let cas = out.filter { $0.isCA || $0.isSelfIssued }
        return cas.isEmpty ? out : cas
    }

    // MARK: persistence

    /// Stores all certificates as concatenated DER.
    public func save(to url: URL) throws {
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        try Data(certificates.flatMap(\.der)).write(to: url, options: .atomic)
    }

    public static func load(from url: URL) -> CSCAStore {
        guard let d = try? Data(contentsOf: url) else { return CSCAStore() }
        var certs = [Certificate]()
        var i = 0
        let bytes = Bytes(d)
        while i < bytes.count, let (t, next) = try? TLV.parse(bytes, at: i) {
            if let c = try? Certificate(der: t.encoded) { certs.append(c) }
            i = next
        }
        return CSCAStore(certificates: certs)
    }
}
