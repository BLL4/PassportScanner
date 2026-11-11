import XCTest
@testable import MRTDKit

final class MRZTests: XCTestCase {
    func testTD3Specimen() throws {
        let m = try MRZ(TestDocument.td3)
        XCTAssertEqual(m.format, .td3)
        XCTAssertEqual(m.documentNumber, "L898902C3")
        XCTAssertEqual(m.issuingState, "UTO")
        XCTAssertEqual(m.surname, "ERIKSSON")
        XCTAssertEqual(m.givenNames, "ANNA MARIA")
        XCTAssertEqual(m.dateOfBirth, "740812")
        XCTAssertEqual(m.sex, "F")
        XCTAssertEqual(m.dateOfExpiry, "120415")
        XCTAssertEqual(m.optionalData, "ZE184226B")
        XCTAssertTrue(m.allValid)
    }

    func testTD1Specimen() throws {
        let m = try MRZ("I<UTOD231458907<<<<<<<<<<<<<<<\n7408122F1204159UTO<<<<<<<<<<<6\nERIKSSON<<ANNA<MARIA<<<<<<<<<<")
        XCTAssertEqual(m.format, .td1)
        XCTAssertEqual(m.documentCode, "I")
        XCTAssertEqual(m.documentNumber, "D23145890")
        XCTAssertEqual(m.nationality, "UTO")
        XCTAssertTrue(m.allValid)
        XCTAssertEqual(m.key.mrzInformation, "D23145890774081221204159")
    }

    func testTD1LongDocumentNumber() throws {
        // 12-character document number: overflow into optional data, check digit after it.
        let doc = "ABC123456789"
        let cd = MRZ.checkDigit(doc)
        var l1 = "I<UTO" + doc.prefix(9) + "<" + doc.suffix(3) + String(cd)
        l1 += String(repeating: "<", count: 30 - l1.count)
        var l2 = "7408122F1204159UTO" + String(repeating: "<", count: 11)
        let composite = String(l1.dropFirst(5)) + l2.prefix(7) + l2.dropFirst(8).prefix(7) + l2.dropFirst(18).prefix(11)
        l2 += String(MRZ.checkDigit(composite))
        let m = try MRZ(lines: [l1, l2, "ERIKSSON<<ANNA" + String(repeating: "<", count: 16)])
        XCTAssertEqual(m.documentNumber, doc)
        XCTAssertTrue(m.allValid)
    }

    func testOCRCorrection() {
        // Typical OCR errors: O for 0 in dates, spaces, « for <<, missing trailing fillers, noise lines.
        let lines = [
            "PASSPORT  PASSEPORT",
            "P<UTOERIKSSON«ANNA<MARIA<<<<<<<<<<<<<<<<<<<",
            "L898902C36UTO74O8122F12O4159ZE184226B<<<<<1O",
        ]
        let m = MRZRecognizer.find(in: lines)
        XCTAssertNotNil(m)
        XCTAssertEqual(m?.documentNumber, "L898902C3")
        XCTAssertEqual(m?.dateOfBirth, "740812")
        XCTAssertEqual(m?.dateOfExpiry, "120415")
        XCTAssertEqual(m?.allValid, true)
    }

    func testOCRDocumentNumberAmbiguity() {
        // Document number with O read instead of 0 must be fixed via its check digit.
        let lines = ["I<UTOD23145B9O7<<<<<<<<<<<<<<<", "7408122F1204159UTO<<<<<<<<<<<6", "ERIKSSON<<ANNA<MARIA<<<<<<<<<<"]
        let m = MRZRecognizer.find(in: lines)
        XCTAssertEqual(m?.documentNumber, "D23145890")
    }

    func testTD1WithoutNameLine() {
        // Third line unreadable (e.g. too small or cut off): lines 1 and 2 are enough for the key.
        let lines = ["I<UTOD231458907<<<<<<<<<<<<<<<", "7408122F12O4159UTO<<<<<<<<<<<6", "ER1KS50N«ANNA MAR"]
        let m = MRZRecognizer.find(in: lines)
        XCTAssertEqual(m?.documentNumber, "D23145890")
        XCTAssertEqual(m?.dateOfExpiry, "120415")
        XCTAssertEqual(m?.allValid, true)
        // Lines collected from different frames, in any order and with duplicates.
        let mixed = ["7408122F1204159UTO<<<<<<<<<<<6", "I<UTOD231458907<<<<<<<<<<<<<<<", "7408122F1204159UTO<<<<<<<<<<<6"]
        XCTAssertEqual(MRZRecognizer.find(in: mixed)?.documentNumber, "D23145890")
    }

    func testKeyValidation() {
        XCTAssertNil(MRZKey(documentNumber: "L898902C3", dateOfBirth: "740812", dateOfExpiry: "120415").validationError)
        XCTAssertNotNil(MRZKey(documentNumber: "L898902C3", dateOfBirth: "741312", dateOfExpiry: "120415").validationError)
        XCTAssertNotNil(MRZKey(documentNumber: "L89-8902", dateOfBirth: "740812", dateOfExpiry: "120415").validationError)
    }
}
