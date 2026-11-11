import XCTest
@testable import MRTDKit

/// Optional: set MASTERLIST=/path/to/file.ml to check parsing and signatures of a real master list.
/// Every certificate is verified against the CSCA its issuer name / authority key identifier points to
/// (self-signed roots against themselves, link certificates against the previous key).
final class RealMasterListTests: XCTestCase {
    func testRealMasterList() throws {
        guard let path = ProcessInfo.processInfo.environment["MASTERLIST"] else { throw XCTSkip("MASTERLIST not set") }
        let certs = CSCAStore.certificates(fromFile: Bytes(try Data(contentsOf: URL(fileURLWithPath: path))))
        let store = CSCAStore(certificates: certs)
        var valid = 0, failures: [String: Int] = [:]
        for c in certs {
            let (status, _) = store.verify(dsc: c)
            if status == .valid { valid += 1; continue }
            let sig = c.signatureAlgorithm.child(0x06).map { ASN1.decodeOID($0.value) } ?? ""
            let issuerKeyPresent = c.authorityKeyIdentifier.map { aki in certs.contains { $0.subjectKeyIdentifier == aki } }
            failures["sig=\(sig) issuerKeyInList=\(issuerKeyPresent.map(String.init) ?? "noAKI") \(status)".prefix(110).description, default: 0] += 1
        }
        print("certificates: \(certs.count), countries: \(store.countries.count), verified: \(valid)")
        failures.sorted { $0.value > $1.value }.forEach { print("  \($0.value)× \($0.key)") }
        XCTAssertGreaterThan(certs.count, 100)
        XCTAssertGreaterThan(Double(valid) / Double(certs.count), 0.97)
    }
}
