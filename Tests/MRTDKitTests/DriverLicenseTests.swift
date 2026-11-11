import XCTest
@testable import MRTDKit

final class DriverLicenseTests: XCTestCase {
    // Modelled on the sample in the AAMVA DL/ID Card Design Standard (2016), version 08.
    static let sample = "@\n\u{1E}\rANSI 636014080102DL00410278ZC03190024DLDAQF987654321\nDCSPUBLIC\nDDEN\nDACJOHN\nDDFN\nDADQUINCY\nDDGN\nDCAD\nDCBNONE\nDCDNONE\nDBD08242015\nDBB01311970\nDBA01312035\nDBC1\nDAU069 IN\nDAYGRN\nDAG789 E OAK ST\nDAIANYTOWN\nDAJCA\nDAK902230000  \nDCF83D9BN217QO983B1\nDCGUSA\nDAW180\nDAZBRO\nDCK12345678900000000000\nDDAF\nDDB06062008\nDDK1\r\nZCZCAY\nZCBCORR LENS\r"

    func testParseAAMVA() throws {
        let dl = try DriverLicense(barcode: Self.sample)
        XCTAssertEqual(dl.documentType, "DL")
        XCTAssertEqual(dl.issuerID, "636014")
        XCTAssertEqual(dl.aamvaVersion, 8)
        XCTAssertEqual(dl.licenseNumber, "F987654321")
        XCTAssertEqual(dl.familyName, "PUBLIC")
        XCTAssertEqual(dl.givenNames, "JOHN QUINCY")
        XCTAssertEqual(DriverLicense.format(dl.dateOfBirth), "1970-01-31")
        XCTAssertEqual(DriverLicense.format(dl.dateOfExpiry), "2035-01-31")
        XCTAssertEqual(dl.sex, "M")
        XCTAssertEqual(dl.address, "789 E OAK ST\nANYTOWN, CA 90223")
        XCTAssertEqual(dl.isRealIDCompliant, true)
        XCTAssertNil(dl.value("DCB")) // NONE
        XCTAssertEqual(dl.value("ZCB"), "CORR LENS")
        XCTAssertEqual(dl.value("ZCA"), "Y")
        XCTAssertEqual(dl.value("DDK"), "1")
        XCTAssertEqual(dl.displayValue("DAU"), "5′9″ (69 in)")
        XCTAssertEqual(dl.displayValue("DDA"), "REAL ID compliant")
        XCTAssertNil(dl.displayValue("DDE"))
        XCTAssertEqual(dl.order.first, "DAQ")
    }

    func testOldVersionAndCanadianDates() throws {
        let old = "@\n\u{1E}\rANSI 6360200101DL00290181DLDAQD1234567\nDAAPUBLIC,JANE,Q\nDBB19800215\nDBA20300215\nDBC2\nDAJON\nDCGCAN\r"
        let dl = try DriverLicense(barcode: old)
        XCTAssertEqual(dl.familyName, "PUBLIC")
        XCTAssertEqual(dl.givenNames, "JANE Q")
        XCTAssertEqual(DriverLicense.format(dl.dateOfBirth), "1980-02-15")
        XCTAssertEqual(dl.sex, "F")
    }

    func testRejectsOtherBarcodes() {
        XCTAssertThrowsError(try DriverLicense(barcode: "https://example.com"))
    }
}
