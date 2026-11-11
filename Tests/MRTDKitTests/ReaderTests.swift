import XCTest
@testable import MRTDKit

final class ReaderTests: XCTestCase {
    let key = MRZKey(documentNumber: "L898902C3", dateOfBirth: "740812", dateOfExpiry: "120415")

    private func check(_ data: PassportData, imageSize: Int) {
        XCTAssertEqual(data.mrz?.surname, "ERIKSSON")
        XCTAssertEqual(data.mrz?.givenNames, "ANNA MARIA")
        XCTAssertEqual(data.faceImage?.format, .jpeg)
        XCTAssertEqual(data.faceImage?.width, 480)
        XCTAssertEqual(data.faceImage?.data.count, imageSize + 4)
        XCTAssertEqual(data.personalDetails?.items.first?.value, "ERIKSSON, ANNA MARIA")
        XCTAssertEqual(data.passiveAuth?.dataGroupHashes, [.dg1: true, .dg2: true, .dg11: true])
        XCTAssertTrue(data.errors.isEmpty, "\(data.errors)")
    }

    func testBACRead() async throws {
        let chip = MockChip(mode: .bacOnly, mrzKey: key, files: TestDocument.files())
        let data = try await PassportReader(transport: chip).read(key: .mrz(key))
        XCTAssertEqual(data.accessControl, "BAC (3DES)")
        check(data, imageSize: 40_000)
    }

    /// The log must contain no personal data and nothing derived from the access key.
    func testLogContainsNoPersonalData() async throws {
        for chip in [MockChip(mode: .bacOnly, mrzKey: key, files: TestDocument.files(imageSize: 3000)),
                     MockChip(mode: .pace(PACEInfo(oid: "0.4.0.127.0.7.2.2.4.2.2", version: 2, parameterID: 13)), mrzKey: key,
                              files: TestDocument.files(imageSize: 3000))] {
            var log: [String] = []
            _ = try await PassportReader(transport: chip) { log.append($0) }.read(key: .mrz(key))
            let text = log.joined(separator: "\n")
            for secret in ["ERIKSSON", "ANNA", "L898902C3", "740812", "120415", "ZENITH"] {
                XCTAssertFalse(text.contains(secret), secret)
                XCTAssertFalse(text.contains(Bytes(secret.utf8).hex), "\(secret) in hex")
            }
            // No long hex blobs (authentication cryptograms, keys, file contents) anywhere.
            let longHex = try NSRegularExpression(pattern: "[0-9A-F]{40,}")
            XCTAssertEqual(longHex.numberOfMatches(in: text, range: NSRange(text.startIndex..., in: text)), 0, text)
        }
    }

    func testBACWrongKeyIsRejected() async throws {
        let chip = MockChip(mode: .bacOnly, mrzKey: key, files: TestDocument.files())
        let wrong = MRZKey(documentNumber: "L898902C3", dateOfBirth: "740813", dateOfExpiry: "120415")
        do {
            _ = try await PassportReader(transport: chip).read(key: .mrz(wrong))
            XCTFail("expected access denied")
        } catch MRTDError.accessDenied {
        }
    }

    func testPACEWithMRZ() async throws {
        for (oid, param) in [("0.4.0.127.0.7.2.2.4.2.2", 13), ("0.4.0.127.0.7.2.2.4.2.4", 16), ("0.4.0.127.0.7.2.2.4.2.1", 12), ("0.4.0.127.0.7.2.2.4.2.3", 18)] {
            let info = PACEInfo(oid: oid, version: 2, parameterID: param)
            let chip = MockChip(mode: .pace(info), mrzKey: key, files: TestDocument.files(imageSize: 5000))
            let data = try await PassportReader(transport: chip).read(key: .mrz(key))
            XCTAssertTrue(data.accessControl.hasPrefix("PACE"), data.accessControl)
            check(data, imageSize: 5000)
        }
    }

    func testPACEWithCAN() async throws {
        let info = PACEInfo(oid: "0.4.0.127.0.7.2.2.4.2.2", version: 2, parameterID: 13)
        let chip = MockChip(mode: .pace(info), mrzKey: key, can: "654321", files: TestDocument.files(imageSize: 1000))
        let data = try await PassportReader(transport: chip).read(key: .can("654321"))
        check(data, imageSize: 1000)

        let chip2 = MockChip(mode: .pace(info), mrzKey: key, can: "654321", files: TestDocument.files(imageSize: 1000))
        do {
            _ = try await PassportReader(transport: chip2).read(key: .can("111111"))
            XCTFail("expected access denied")
        } catch MRTDError.accessDenied {
        }
    }

    func testPACEInfoParsing() {
        let info = PACEInfo(oid: "0.4.0.127.0.7.2.2.4.2.2", version: 2, parameterID: 13)
        let chip = MockChip(mode: .pace(info), mrzKey: key, files: [:])
        let parsed = PACEInfo.parse(cardAccess: chip.cardAccess!)
        XCTAssertEqual(parsed.count, 1)
        XCTAssertEqual(parsed[0].mapping, .ecdhGM)
        XCTAssertEqual(parsed[0].cipher, .aes128)
        XCTAssertEqual(parsed[0].curve?.name, "brainpoolP256r1")
    }
}
