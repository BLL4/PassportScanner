import XCTest
@testable import MRTDKit

final class SafeFileNameTests: XCTestCase {
    func testSanitizesTraversal() {
        XCTAssertEqual(SafeFileName.make(["../../etc", "passwd"]), "etc_passwd")
        XCTAssertEqual(SafeFileName.make(["..", "/"]), "document")
        XCTAssertEqual(SafeFileName.make(["MÜLLER-LÜDENSCHEIDT", "C01X00T47"]), "M_LLER-L_DENSCHEIDT_C01X00T47")
        XCTAssertEqual(SafeFileName.make([nil, ""], fallback: "license"), "license")
        XCTAssertEqual(SafeFileName.make([String(repeating: "A", count: 500)]).count, 64)
        XCTAssertEqual(SafeFileName.make(["ERIKSSON", "L898902C3"]), "ERIKSSON_L898902C3")
    }

    func testContainment() throws {
        let base = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: base, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: base) }
        XCTAssertEqual(try SafeFileName.child(of: base, "ok").lastPathComponent, "ok")
        XCTAssertThrowsError(try SafeFileName.child(of: base, "../escape"))
        XCTAssertThrowsError(try SafeFileName.child(of: base, ".."))
        XCTAssertThrowsError(try SafeFileName.child(of: base, "a/../../b"))
    }

    /// A chip whose DG1 name field contains a path: the parsed surname keeps it, so the export
    /// must not use it as a path.
    func testCraftedChipSurname() throws {
        let mrz = try MRZ(lines: ["P<UTO../../../tmp/pwned<<X<<<<<<<<<<<<<<<<<<", "L898902C36UTO7408122F1204159ZE184226B<<<<<10"])
        XCTAssertTrue(mrz.surname.contains("../"))
        let name = SafeFileName.make([mrz.surname, mrz.documentNumber])
        XCTAssertFalse(name.contains("/") || name.contains(".."))
    }
}
